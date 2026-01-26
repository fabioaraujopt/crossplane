/*
Copyright 2024 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package validate

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/crossplane/crossplane/v2/cmd/crank/common/load"
)

// DeletionSafetyIssue represents a deletion safety validation issue.
type DeletionSafetyIssue struct {
	Composition string
	Resource    string
	SourceFile  string
	SourceLine  int
	Message     string
	Severity    string // "error" or "warning"
	Category    string // "rollbackLimit", "iamUsage", "labelMismatch", "crossComposition"
	Suggestion  string // Suggested fix
}

func (d DeletionSafetyIssue) Error() string {
	loc := d.SourceFile
	if d.SourceLine > 0 {
		loc = fmt.Sprintf("%s:%d", d.SourceFile, d.SourceLine)
	}
	if d.Resource != "" {
		return fmt.Sprintf("%s: [%s] %s (resource: %s)", loc, d.Category, d.Message, d.Resource)
	}
	return fmt.Sprintf("%s: [%s] %s", loc, d.Category, d.Message)
}

// DeletionSafetyResult holds the results of deletion safety validation.
type DeletionSafetyResult struct {
	Errors        []DeletionSafetyIssue
	Warnings      []DeletionSafetyIssue
	DeletionOrder []DeletionWave
}

// HasErrors returns true if there are any errors.
func (r *DeletionSafetyResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// HasWarnings returns true if there are any warnings.
func (r *DeletionSafetyResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

// DeletionWave represents a group of resources that can be deleted together.
type DeletionWave struct {
	Wave      int
	Resources []DeletionResource
}

// DeletionResource represents a resource in the deletion order.
type DeletionResource struct {
	Name       string
	Kind       string
	APIVersion string
	Labels     map[string]string
	UsedBy     []string // Resources that use this (must be deleted first)
}

// UsageInfo represents a ClusterUsage object's information.
type UsageInfo struct {
	Name           string
	SourceFile     string
	SourceLine     int
	OfAPIVersion   string
	OfKind         string
	OfLabels       map[string]string
	ByAPIVersion   string
	ByKind         string
	ByLabels       map[string]string
	ReplayDeletion bool
}

// HelmReleaseInfo represents a Helm Release resource's information.
type HelmReleaseInfo struct {
	Name           string
	Composition    string
	SourceFile     string
	SourceLine     int
	Labels         map[string]string
	RollbackLimit  *int64
	Wait           bool
	WaitTimeout    string
	ChartName      string
	Namespace      string
	ValuesRoleARN  string // IAM role ARN found in values (for IRSA detection)
}

// ResourceInfo represents a generic resource's information.
type ResourceInfo struct {
	Name       string
	Kind       string
	APIVersion string
	Labels     map[string]string
	SourceFile string
	SourceLine int
}

// DeletionSafetyValidator validates deletion safety patterns in compositions.
type DeletionSafetyValidator struct {
	compositions []*ParsedComposition
	objects      []*unstructured.Unstructured
	helmReleases []HelmReleaseInfo
	usages       []UsageInfo
	iamRoles     []ResourceInfo
	iamPolicies  []ResourceInfo
	allResources []ResourceInfo
}

// NewDeletionSafetyValidator creates a new DeletionSafetyValidator.
func NewDeletionSafetyValidator(compositions []*ParsedComposition, objects []*unstructured.Unstructured) *DeletionSafetyValidator {
	v := &DeletionSafetyValidator{
		compositions: compositions,
		objects:      objects,
		helmReleases: make([]HelmReleaseInfo, 0),
		usages:       make([]UsageInfo, 0),
		iamRoles:     make([]ResourceInfo, 0),
		iamPolicies:  make([]ResourceInfo, 0),
		allResources: make([]ResourceInfo, 0),
	}

	// Extract resources from compositions
	v.extractResources()

	return v
}

// extractResources extracts Helm releases, Usage objects, IAM roles, etc. from compositions.
func (v *DeletionSafetyValidator) extractResources() {
	for _, comp := range v.compositions {
		sourceFile := comp.SourceFile
		sourceLine := comp.SourceLine

		for _, res := range comp.Resources {
			if res.Base == nil {
				continue
			}

			gvk := res.Base.GroupVersionKind()
			labels := res.Base.GetLabels()
			if labels == nil {
				labels = make(map[string]string)
			}

			// Track all resources
			v.allResources = append(v.allResources, ResourceInfo{
				Name:       res.Name,
				Kind:       gvk.Kind,
				APIVersion: gvk.GroupVersion().String(),
				Labels:     labels,
				SourceFile: sourceFile,
				SourceLine: sourceLine,
			})

			// Extract Helm releases
			if gvk.Group == "helm.crossplane.io" && gvk.Kind == "Release" {
				helmInfo := v.extractHelmRelease(res, comp.Name, sourceFile, sourceLine)
				v.helmReleases = append(v.helmReleases, helmInfo)
			}

			// Extract ClusterUsage objects
			if gvk.Group == "protection.crossplane.io" && gvk.Kind == "ClusterUsage" {
				usageInfo := v.extractUsage(res, sourceFile, sourceLine)
				v.usages = append(v.usages, usageInfo)
			}

			// Extract IAM Roles
			if gvk.Group == "iam.aws.upbound.io" && gvk.Kind == "Role" {
				v.iamRoles = append(v.iamRoles, ResourceInfo{
					Name:       res.Name,
					Kind:       gvk.Kind,
					APIVersion: gvk.GroupVersion().String(),
					Labels:     labels,
					SourceFile: sourceFile,
					SourceLine: sourceLine,
				})
			}

			// Extract IAM Policies
			if gvk.Group == "iam.aws.upbound.io" && (gvk.Kind == "Policy" || gvk.Kind == "RolePolicyAttachment") {
				v.iamPolicies = append(v.iamPolicies, ResourceInfo{
					Name:       res.Name,
					Kind:       gvk.Kind,
					APIVersion: gvk.GroupVersion().String(),
					Labels:     labels,
					SourceFile: sourceFile,
					SourceLine: sourceLine,
				})
			}
		}
	}
}

// extractHelmRelease extracts Helm release information from a composed resource.
func (v *DeletionSafetyValidator) extractHelmRelease(res ComposedResource, compName, sourceFile string, sourceLine int) HelmReleaseInfo {
	info := HelmReleaseInfo{
		Name:        res.Name,
		Composition: compName,
		SourceFile:  sourceFile,
		SourceLine:  sourceLine,
		Labels:      res.Base.GetLabels(),
	}

	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}

	spec, _, _ := unstructured.NestedMap(res.Base.Object, "spec")
	if spec == nil {
		return info
	}

	// Extract rollbackLimit
	if rollbackLimit, found, _ := unstructured.NestedInt64(res.Base.Object, "spec", "rollbackLimit"); found {
		info.RollbackLimit = &rollbackLimit
	}

	// Extract forProvider settings
	forProvider, _, _ := unstructured.NestedMap(res.Base.Object, "spec", "forProvider")
	if forProvider != nil {
		// Extract wait
		if wait, found, _ := unstructured.NestedBool(res.Base.Object, "spec", "forProvider", "wait"); found {
			info.Wait = wait
		}

		// Extract waitTimeout
		if waitTimeout, found, _ := unstructured.NestedString(res.Base.Object, "spec", "forProvider", "waitTimeout"); found {
			info.WaitTimeout = waitTimeout
		}

		// Extract chart name
		if chartName, found, _ := unstructured.NestedString(res.Base.Object, "spec", "forProvider", "chart", "name"); found {
			info.ChartName = chartName
		}

		// Extract namespace
		if namespace, found, _ := unstructured.NestedString(res.Base.Object, "spec", "forProvider", "namespace"); found {
			info.Namespace = namespace
		}

		// Look for IAM role ARN in values (IRSA detection)
		info.ValuesRoleARN = v.findRoleARNInValues(forProvider)
	}

	return info
}

// findRoleARNInValues searches for IAM role ARN patterns in Helm values.
func (v *DeletionSafetyValidator) findRoleARNInValues(forProvider map[string]interface{}) string {
	// Convert to string and search for role ARN patterns
	valuesStr := fmt.Sprintf("%v", forProvider)

	// Pattern for IAM role ARN
	roleARNPattern := regexp.MustCompile(`arn:aws:iam::\d+:role/[a-zA-Z0-9_+-]+`)
	if match := roleARNPattern.FindString(valuesStr); match != "" {
		return match
	}

	// Also check for roleArn field patterns
	roleArnFieldPattern := regexp.MustCompile(`roleArn.*?arn:aws:iam`)
	if roleArnFieldPattern.MatchString(valuesStr) {
		return "detected"
	}

	// Check for eks.amazonaws.com/role-arn annotation pattern
	eksRolePattern := regexp.MustCompile(`eks\.amazonaws\.com/role-arn`)
	if eksRolePattern.MatchString(valuesStr) {
		return "detected"
	}

	return ""
}

// extractUsage extracts ClusterUsage information from a composed resource.
func (v *DeletionSafetyValidator) extractUsage(res ComposedResource, sourceFile string, sourceLine int) UsageInfo {
	info := UsageInfo{
		Name:       res.Name,
		SourceFile: sourceFile,
		SourceLine: sourceLine,
		OfLabels:   make(map[string]string),
		ByLabels:   make(map[string]string),
	}

	spec, _, _ := unstructured.NestedMap(res.Base.Object, "spec")
	if spec == nil {
		return info
	}

	// Extract replayDeletion
	if replayDeletion, found, _ := unstructured.NestedBool(res.Base.Object, "spec", "replayDeletion"); found {
		info.ReplayDeletion = replayDeletion
	}

	// Extract "of" reference
	if ofAPIVersion, found, _ := unstructured.NestedString(res.Base.Object, "spec", "of", "apiVersion"); found {
		info.OfAPIVersion = ofAPIVersion
	}
	if ofKind, found, _ := unstructured.NestedString(res.Base.Object, "spec", "of", "kind"); found {
		info.OfKind = ofKind
	}
	if ofLabels, found, _ := unstructured.NestedStringMap(res.Base.Object, "spec", "of", "resourceSelector", "matchLabels"); found {
		info.OfLabels = ofLabels
	}

	// Extract "by" reference
	if byAPIVersion, found, _ := unstructured.NestedString(res.Base.Object, "spec", "by", "apiVersion"); found {
		info.ByAPIVersion = byAPIVersion
	}
	if byKind, found, _ := unstructured.NestedString(res.Base.Object, "spec", "by", "kind"); found {
		info.ByKind = byKind
	}
	if byLabels, found, _ := unstructured.NestedStringMap(res.Base.Object, "spec", "by", "resourceSelector", "matchLabels"); found {
		info.ByLabels = byLabels
	}

	return info
}

// Validate runs all deletion safety validations.
func (v *DeletionSafetyValidator) Validate() *DeletionSafetyResult {
	result := &DeletionSafetyResult{
		Errors:   make([]DeletionSafetyIssue, 0),
		Warnings: make([]DeletionSafetyIssue, 0),
	}

	// 1. Check rollbackLimit on Helm releases
	rollbackIssues := v.validateRollbackLimits()
	for _, issue := range rollbackIssues {
		if issue.Severity == "error" {
			result.Errors = append(result.Errors, issue)
		} else {
			result.Warnings = append(result.Warnings, issue)
		}
	}

	// 2. Check IAM → Helm Usage protection (IRSA)
	iamIssues := v.validateIAMUsageProtection()
	for _, issue := range iamIssues {
		if issue.Severity == "error" {
			result.Errors = append(result.Errors, issue)
		} else {
			result.Warnings = append(result.Warnings, issue)
		}
	}

	// 3. Check label matching for Usage selectors
	labelIssues := v.validateUsageLabelMatching()
	for _, issue := range labelIssues {
		if issue.Severity == "error" {
			result.Errors = append(result.Errors, issue)
		} else {
			result.Warnings = append(result.Warnings, issue)
		}
	}

	// 4. Check cross-composition dependencies
	crossCompIssues := v.validateCrossCompositionDependencies()
	for _, issue := range crossCompIssues {
		if issue.Severity == "error" {
			result.Errors = append(result.Errors, issue)
		} else {
			result.Warnings = append(result.Warnings, issue)
		}
	}

	// 5. Build deletion order
	result.DeletionOrder = v.buildDeletionOrder()

	return result
}

// validateRollbackLimits checks that all Helm releases have rollbackLimit set.
func (v *DeletionSafetyValidator) validateRollbackLimits() []DeletionSafetyIssue {
	var issues []DeletionSafetyIssue

	for _, helm := range v.helmReleases {
		if helm.RollbackLimit == nil {
			issues = append(issues, DeletionSafetyIssue{
				Composition: helm.Composition,
				Resource:    helm.Name,
				SourceFile:  helm.SourceFile,
				SourceLine:  helm.SourceLine,
				Message:     fmt.Sprintf("Helm release '%s' missing rollbackLimit (default is 5, recommend 100)", helm.Name),
				Severity:    "warning",
				Category:    "rollbackLimit",
				Suggestion:  "Add 'spec.rollbackLimit: 100' to prevent permanent failure after 5 retries",
			})
		} else if *helm.RollbackLimit < 10 {
			issues = append(issues, DeletionSafetyIssue{
				Composition: helm.Composition,
				Resource:    helm.Name,
				SourceFile:  helm.SourceFile,
				SourceLine:  helm.SourceLine,
				Message:     fmt.Sprintf("Helm release '%s' has low rollbackLimit (%d), recommend at least 100", helm.Name, *helm.RollbackLimit),
				Severity:    "warning",
				Category:    "rollbackLimit",
				Suggestion:  "Increase 'spec.rollbackLimit' to at least 100 for stability",
			})
		}
	}

	return issues
}

// validateIAMUsageProtection checks that Helm releases using IRSA have Usage protection for IAM roles.
func (v *DeletionSafetyValidator) validateIAMUsageProtection() []DeletionSafetyIssue {
	var issues []DeletionSafetyIssue

	// Find Helm releases that use IAM roles (IRSA)
	for _, helm := range v.helmReleases {
		if helm.ValuesRoleARN == "" {
			continue // No IRSA detected
		}

		// Check if there's a Usage protecting IAM by this Helm release
		hasProtection := false
		for _, usage := range v.usages {
			// Check if this Usage protects IAM by a Helm release
			isIAMProtection := (usage.OfKind == "Role" || usage.OfKind == "Policy" || usage.OfKind == "RolePolicyAttachment") &&
				strings.Contains(usage.OfAPIVersion, "iam.aws.upbound.io")

			isHelmUser := usage.ByKind == "Release" &&
				strings.Contains(usage.ByAPIVersion, "helm.crossplane.io")

			if isIAMProtection && isHelmUser {
				hasProtection = true
				break
			}
		}

		if !hasProtection {
			issues = append(issues, DeletionSafetyIssue{
				Composition: helm.Composition,
				Resource:    helm.Name,
				SourceFile:  helm.SourceFile,
				SourceLine:  helm.SourceLine,
				Message:     fmt.Sprintf("Helm release '%s' uses IRSA but has no ClusterUsage protecting IAM Role", helm.Name),
				Severity:    "warning",
				Category:    "iamUsage",
				Suggestion:  "Add ClusterUsage with 'of: IAM Role' and 'by: this Helm Release' to keep IAM alive during deletion",
			})
		}
	}

	return issues
}

// validateUsageLabelMatching checks that Usage selectors have matching labels on target resources.
func (v *DeletionSafetyValidator) validateUsageLabelMatching() []DeletionSafetyIssue {
	var issues []DeletionSafetyIssue

	for _, usage := range v.usages {
		// Check "of" selector labels
		if len(usage.OfLabels) > 0 {
			if !v.hasMatchingResource(usage.OfKind, usage.OfAPIVersion, usage.OfLabels) {
				issues = append(issues, DeletionSafetyIssue{
					Resource:   usage.Name,
					SourceFile: usage.SourceFile,
					SourceLine: usage.SourceLine,
					Message:    fmt.Sprintf("ClusterUsage '%s' 'of' selector labels %v don't match any %s resource", usage.Name, usage.OfLabels, usage.OfKind),
					Severity:   "error",
					Category:   "labelMismatch",
					Suggestion: fmt.Sprintf("Add labels %v to the target %s resource", usage.OfLabels, usage.OfKind),
				})
			}
		}

		// Check "by" selector labels
		if len(usage.ByLabels) > 0 {
			if !v.hasMatchingResource(usage.ByKind, usage.ByAPIVersion, usage.ByLabels) {
				issues = append(issues, DeletionSafetyIssue{
					Resource:   usage.Name,
					SourceFile: usage.SourceFile,
					SourceLine: usage.SourceLine,
					Message:    fmt.Sprintf("ClusterUsage '%s' 'by' selector labels %v don't match any %s resource", usage.Name, usage.ByLabels, usage.ByKind),
					Severity:   "error",
					Category:   "labelMismatch",
					Suggestion: fmt.Sprintf("Add labels %v to the 'by' %s resource", usage.ByLabels, usage.ByKind),
				})
			}
		}
	}

	return issues
}

// hasMatchingResource checks if any resource matches the given kind, apiVersion, and labels.
func (v *DeletionSafetyValidator) hasMatchingResource(kind, apiVersion string, labels map[string]string) bool {
	for _, res := range v.allResources {
		if res.Kind != kind {
			continue
		}

		// Check if all required labels are present
		allLabelsMatch := true
		for k, reqV := range labels {
			if resV, ok := res.Labels[k]; !ok || resV != reqV {
				allLabelsMatch = false
				break
			}
		}

		if allLabelsMatch {
			return true
		}
	}
	return false
}

// KnownDeletionDependency represents a known deletion dependency pattern.
type KnownDeletionDependency struct {
	ProtectedKind    string // Kind that should be protected
	ProtectedGroup   string // API group of protected kind
	ProtectorKind    string // Kind that uses the protected resource
	ProtectorGroup   string // API group of protector kind
	Reason           string // Why this dependency matters
	MustHaveUsage    bool   // Whether a Usage is required (vs optional)
}

// knownDeletionDependencies defines known cross-composition deletion dependencies.
var knownDeletionDependencies = []KnownDeletionDependency{
	{
		ProtectedKind:  "StampNetworkingV2",
		ProtectedGroup: "cloud.physicsx.ai",
		ProtectorKind:  "StampLoadBalancerV2",
		ProtectorGroup: "cloud.physicsx.ai",
		Reason:         "LoadBalancer Controller creates security groups in VPC that must be cleaned up before VPC deletion",
		MustHaveUsage:  true,
	},
	{
		ProtectedKind:  "StampLoadBalancerV2",
		ProtectedGroup: "cloud.physicsx.ai",
		ProtectorKind:  "StampIstioV2",
		ProtectorGroup: "cloud.physicsx.ai",
		Reason:         "Istio creates LoadBalancer Services that LoadBalancer Controller must clean up",
		MustHaveUsage:  true,
	},
	{
		ProtectedKind:  "StampClusterV2",
		ProtectedGroup: "cloud.physicsx.ai",
		ProtectorKind:  "StampCommonV2",
		ProtectorGroup: "cloud.physicsx.ai",
		Reason:         "All services run on the cluster and must be deleted before cluster",
		MustHaveUsage:  true,
	},
	{
		ProtectedKind:  "StampNetworkingV2",
		ProtectedGroup: "cloud.physicsx.ai",
		ProtectorKind:  "StampClusterV2",
		ProtectorGroup: "cloud.physicsx.ai",
		Reason:         "Cluster uses VPC resources that must outlive the cluster",
		MustHaveUsage:  true,
	},
}

// extractGroup extracts the API group from an apiVersion string (e.g., "cloud.physicsx.ai/v1alpha1" -> "cloud.physicsx.ai")
func extractGroup(apiVersion string) string {
	parts := strings.Split(apiVersion, "/")
	if len(parts) >= 1 {
		return parts[0]
	}
	return apiVersion
}

// validateCrossCompositionDependencies checks for missing cross-composition Usage objects.
func (v *DeletionSafetyValidator) validateCrossCompositionDependencies() []DeletionSafetyIssue {
	var issues []DeletionSafetyIssue

	// Build a set of existing Usage relationships
	// Use Kind/Group (not Kind/APIVersion) to match against known dependencies
	existingUsages := make(map[string]bool)
	for _, usage := range v.usages {
		// Extract group from apiVersion (e.g., "cloud.physicsx.ai/v1alpha1" -> "cloud.physicsx.ai")
		ofGroup := extractGroup(usage.OfAPIVersion)
		byGroup := extractGroup(usage.ByAPIVersion)
		key := fmt.Sprintf("%s/%s->%s/%s", usage.OfKind, ofGroup, usage.ByKind, byGroup)
		existingUsages[key] = true
	}

	// Check for known dependencies
	for _, dep := range knownDeletionDependencies {
		key := fmt.Sprintf("%s/%s->%s/%s", dep.ProtectedKind, dep.ProtectedGroup, dep.ProtectorKind, dep.ProtectorGroup)

		// Check if both kinds exist in our compositions
		hasProtected := v.hasResourceKind(dep.ProtectedKind)
		hasProtector := v.hasResourceKind(dep.ProtectorKind)

		if hasProtected && hasProtector && !existingUsages[key] {
			severity := "warning"
			if dep.MustHaveUsage {
				severity = "warning" // Still warning since we can't be 100% sure
			}

			issues = append(issues, DeletionSafetyIssue{
				Message:  fmt.Sprintf("Missing ClusterUsage: %s should be protected by %s. %s", dep.ProtectedKind, dep.ProtectorKind, dep.Reason),
				Severity: severity,
				Category: "crossComposition",
				Suggestion: fmt.Sprintf("Add ClusterUsage with 'of: %s' and 'by: %s' with replayDeletion: true",
					dep.ProtectedKind, dep.ProtectorKind),
			})
		}
	}

	return issues
}

// hasResourceKind checks if any composition has a resource of the given kind.
func (v *DeletionSafetyValidator) hasResourceKind(kind string) bool {
	for _, res := range v.allResources {
		if res.Kind == kind {
			return true
		}
	}

	// Also check base resources in compositions for child XR kinds
	for _, comp := range v.compositions {
		for _, res := range comp.Resources {
			if res.Base != nil && res.Base.GetKind() == kind {
				return true
			}
		}
	}

	return false
}

// buildDeletionOrder builds the deletion order from Usage objects.
func (v *DeletionSafetyValidator) buildDeletionOrder() []DeletionWave {
	// Build dependency graph: resource -> resources it depends on (must be deleted after)
	dependencies := make(map[string][]string)
	allResources := make(map[string]DeletionResource)

	// Collect all resources
	for _, res := range v.allResources {
		key := fmt.Sprintf("%s/%s", res.Kind, res.Name)
		allResources[key] = DeletionResource{
			Name:       res.Name,
			Kind:       res.Kind,
			APIVersion: res.APIVersion,
			Labels:     res.Labels,
			UsedBy:     make([]string, 0),
		}
	}

	// Build dependencies from Usage objects
	for _, usage := range v.usages {
		if !usage.ReplayDeletion {
			continue // Only consider Usages that affect deletion
		}

		// The "by" resource must be deleted before the "of" resource
		// So "of" depends on "by" being deleted first
		ofKey := fmt.Sprintf("%s/*", usage.OfKind)
		byKey := fmt.Sprintf("%s/*", usage.ByKind)

		dependencies[ofKey] = append(dependencies[ofKey], byKey)

		// Track "usedBy" for visualization
		if res, ok := allResources[ofKey]; ok {
			res.UsedBy = append(res.UsedBy, byKey)
			allResources[ofKey] = res
		}
	}

	// Topological sort to determine waves
	waves := v.topologicalSort(allResources, dependencies)

	return waves
}

// topologicalSort performs topological sort to determine deletion waves.
func (v *DeletionSafetyValidator) topologicalSort(resources map[string]DeletionResource, dependencies map[string][]string) []DeletionWave {
	// Calculate in-degrees (number of resources that must be deleted before this one)
	inDegree := make(map[string]int)
	for key := range resources {
		inDegree[key] = 0
	}

	for _, deps := range dependencies {
		for _, dep := range deps {
			inDegree[dep]++
		}
	}

	// BFS-based topological sort
	var waves []DeletionWave
	remaining := make(map[string]bool)
	for key := range resources {
		remaining[key] = true
	}

	wave := 0
	for len(remaining) > 0 {
		// Find all resources with no remaining dependencies
		var currentWave []DeletionResource
		var toRemove []string

		for key := range remaining {
			if inDegree[key] == 0 {
				if res, ok := resources[key]; ok {
					currentWave = append(currentWave, res)
				}
				toRemove = append(toRemove, key)
			}
		}

		if len(toRemove) == 0 {
			// Cycle detected - add remaining as final wave
			for key := range remaining {
				if res, ok := resources[key]; ok {
					currentWave = append(currentWave, res)
				}
			}
			if len(currentWave) > 0 {
				waves = append(waves, DeletionWave{Wave: wave, Resources: currentWave})
			}
			break
		}

		// Remove processed resources and update in-degrees
		for _, key := range toRemove {
			delete(remaining, key)
			for _, dep := range dependencies[key] {
				inDegree[dep]--
			}
		}

		if len(currentWave) > 0 {
			// Sort for consistent output
			sort.Slice(currentWave, func(i, j int) bool {
				return currentWave[i].Kind+currentWave[i].Name < currentWave[j].Kind+currentWave[j].Name
			})
			waves = append(waves, DeletionWave{Wave: wave, Resources: currentWave})
		}
		wave++
	}

	return waves
}

// PrintDeletionOrder prints the deletion order to the writer.
func (v *DeletionSafetyValidator) PrintDeletionOrder(waves []DeletionWave, w io.Writer) error {
	if len(waves) == 0 {
		return nil
	}

	if _, err := fmt.Fprintf(w, "\n📋 Deletion Order (based on ClusterUsage objects):\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "════════════════════════════════════════════════════\n"); err != nil {
		return err
	}

	for _, wave := range waves {
		if _, err := fmt.Fprintf(w, "\nWave %d (delete first):\n", wave.Wave+1); err != nil {
			return err
		}
		for _, res := range wave.Resources {
			usedByStr := ""
			if len(res.UsedBy) > 0 {
				usedByStr = fmt.Sprintf(" (used by: %s)", strings.Join(res.UsedBy, ", "))
			}
			if _, err := fmt.Fprintf(w, "  └─ %s/%s%s\n", res.Kind, res.Name, usedByStr); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(w, "\n"); err != nil {
		return err
	}

	return nil
}

// PrintResults prints the deletion safety validation results.
func PrintDeletionSafetyResults(result *DeletionSafetyResult, w io.Writer, showDeletionOrder bool) error {
	// Print errors
	for _, err := range result.Errors {
		line := ""
		if err.SourceLine > 0 {
			line = fmt.Sprintf(":%d", err.SourceLine)
		}
		if _, e := fmt.Fprintf(w, "[x] %s%s: [%s] %s\n", err.SourceFile, line, err.Category, err.Message); e != nil {
			return e
		}
		if err.Suggestion != "" {
			if _, e := fmt.Fprintf(w, "    └─ Suggestion: %s\n", err.Suggestion); e != nil {
				return e
			}
		}
	}

	// Print warnings
	for _, warn := range result.Warnings {
		line := ""
		if warn.SourceLine > 0 {
			line = fmt.Sprintf(":%d", warn.SourceLine)
		}
		if _, e := fmt.Fprintf(w, "[!] %s%s: [%s] %s\n", warn.SourceFile, line, warn.Category, warn.Message); e != nil {
			return e
		}
		if warn.Suggestion != "" {
			if _, e := fmt.Fprintf(w, "    └─ Suggestion: %s\n", warn.Suggestion); e != nil {
				return e
			}
		}
	}

	return nil
}

// ValidateDeletionSafetyFromObjects creates a validator from unstructured objects and validates.
func ValidateDeletionSafetyFromObjects(objects []*unstructured.Unstructured) *DeletionSafetyResult {
	// Parse compositions
	parser := NewCompositionParser()
	if err := parser.Parse(objects); err != nil {
		return &DeletionSafetyResult{
			Errors: []DeletionSafetyIssue{{
				Message:  fmt.Sprintf("Failed to parse compositions: %v", err),
				Severity: "error",
				Category: "parse",
			}},
		}
	}

	// Create validator and run
	validator := NewDeletionSafetyValidator(parser.GetCompositions(), objects)
	return validator.Validate()
}

// GetValidatorFromParsed creates a validator from already parsed compositions.
func GetValidatorFromParsed(compositions []*ParsedComposition, objects []*unstructured.Unstructured) *DeletionSafetyValidator {
	return NewDeletionSafetyValidator(compositions, objects)
}

// DetectMissingRollbackLimit is a convenience function to check only rollbackLimit.
func DetectMissingRollbackLimit(compositions []*ParsedComposition) []DeletionSafetyIssue {
	validator := &DeletionSafetyValidator{
		compositions: compositions,
		helmReleases: make([]HelmReleaseInfo, 0),
	}

	// Extract only Helm releases
	for _, comp := range compositions {
		sourceFile := comp.SourceFile
		sourceLine := comp.SourceLine

		for _, res := range comp.Resources {
			if res.Base == nil {
				continue
			}
			gvk := res.Base.GroupVersionKind()
			if gvk.Group == "helm.crossplane.io" && gvk.Kind == "Release" {
				helmInfo := validator.extractHelmRelease(res, comp.Name, sourceFile, sourceLine)
				validator.helmReleases = append(validator.helmReleases, helmInfo)
			}
		}
	}

	return validator.validateRollbackLimits()
}

// GetSourceFileFromObject extracts source file annotation from an unstructured object.
func GetSourceFileFromObject(obj *unstructured.Unstructured) string {
	return load.GetSourceFile(obj)
}

// GetSourceLineFromObject extracts source line annotation from an unstructured object.
func GetSourceLineFromObject(obj *unstructured.Unstructured) int {
	return load.GetSourceLine(obj)
}
