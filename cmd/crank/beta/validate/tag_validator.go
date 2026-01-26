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
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// CloudProviderAPIGroups contains API groups that represent cloud resources requiring tags
var CloudProviderAPIGroups = []string{
	// AWS (Upbound)
	".aws.upbound.io",
	// Azure (Upbound)
	".azure.upbound.io",
	// GCP (Upbound)
	".gcp.upbound.io",
	// AWS (Crossplane contrib - legacy)
	".aws.crossplane.io",
	// Azure (Crossplane contrib - legacy)
	".azure.crossplane.io",
}

// DefaultRequiredTags are the tags that should be present on all cloud resources
var DefaultRequiredTags = []string{
	"ManagedBy",
	"StampName",
	"Environment",
}

// DefaultTagManagerFunctions are the known tag manager function names
var DefaultTagManagerFunctions = []string{
	"crossplane-function-tag-manager",
	"function-tag-manager",
}

// TagValidatorConfig configures tag validation behavior
type TagValidatorConfig struct {
	RequiredTags        []string // Tags that must be present
	CloudProviders      []string // Provider API group suffixes to detect
	TagManagerFunctions []string // Names of tag-manager functions
	SkipCompositions    []string // Composition names to skip
}

// TagValidator validates tagging patterns in compositions
type TagValidator struct {
	config TagValidatorConfig
}

// TagValidationResult contains validation results
type TagValidationResult struct {
	Warnings            []TagWarning
	Errors              []TagError
	CompositionsChecked int
	CloudCompositions   int
	ProperlyTagged      int
	MissingTagManager   int
	MissingPropagation  int
}

// TagWarning represents a tag validation warning
type TagWarning struct {
	File        string
	Line        int
	Composition string
	Rule        string   // e.g., "missing-tag-manager", "missing-required-tags", "tags-not-propagated"
	Message     string
	Affected    []string // Affected resources
	Action      string   // Recommended action
}

// TagError represents a tag validation error
type TagError struct {
	File        string
	Line        int
	Composition string
	Rule        string
	Message     string
}

// TagPropagationNode represents a node in the tag propagation tree
type TagPropagationNode struct {
	Name           string
	Kind           string
	File           string
	HasTagManager  bool
	ReceivesTags   bool
	PassesTags     bool
	Children       []*TagPropagationNode
	CloudResources []string
}

// NewTagValidator creates a new TagValidator with the given config
func NewTagValidator(config TagValidatorConfig) *TagValidator {
	// Apply defaults
	if len(config.RequiredTags) == 0 {
		config.RequiredTags = DefaultRequiredTags
	}
	if len(config.CloudProviders) == 0 {
		config.CloudProviders = CloudProviderAPIGroups
	}
	if len(config.TagManagerFunctions) == 0 {
		config.TagManagerFunctions = DefaultTagManagerFunctions
	}

	return &TagValidator{config: config}
}

// Validate performs tag validation on compositions
func (v *TagValidator) Validate(compositions []*unstructured.Unstructured) TagValidationResult {
	result := TagValidationResult{
		CompositionsChecked: len(compositions),
	}

	// Build a MULTI-map of compositions by their composite type
	// This handles AWS/Azure variants of the same composition kind
	compositionMultiMap := make(map[string][]*unstructured.Unstructured)
	for _, comp := range compositions {
		if comp == nil || comp.GetKind() != "Composition" {
			continue
		}

		// Get composite type ref
		compositeType := v.getCompositeTypeRef(comp)
		if compositeType != "" {
			compositionMultiMap[compositeType] = append(compositionMultiMap[compositeType], comp)
		}
	}

	// Track which compositions we've already warned about (by kind)
	// to avoid duplicate warnings for AWS/Azure variants
	warnedMissingTagManager := make(map[string]bool)

	for _, comp := range compositions {
		if comp == nil || comp.GetKind() != "Composition" {
			continue
		}

		// Skip if in skip list
		compName := comp.GetName()
		if v.shouldSkip(compName) {
			continue
		}

		sourceFile := v.getSourceFile(comp)
		compositeType := v.getCompositeTypeRef(comp)

		// Rule 1: Check if composition creates cloud resources
		cloudResources := v.getCloudResources(comp)
		if len(cloudResources) > 0 {
			result.CloudCompositions++

			// Check for tag-manager
			if !v.hasTagManager(comp) {
				// Only warn once per composite type (avoid duplicate warnings for AWS/Azure)
				if !warnedMissingTagManager[compositeType] {
					result.MissingTagManager++
					result.Warnings = append(result.Warnings, TagWarning{
						File:        sourceFile,
						Composition: compName,
						Rule:        "missing-tag-manager",
						Message:     "Composition creates cloud resources without function-tag-manager",
						Affected:    cloudResources,
						Action:      "Add function-tag-manager to pipeline",
					})
					warnedMissingTagManager[compositeType] = true
				}
			} else {
				// Rule 2: Check required tags in tag-manager
				missingTags := v.getMissingRequiredTags(comp)
				if len(missingTags) > 0 {
					result.Warnings = append(result.Warnings, TagWarning{
						File:        sourceFile,
						Composition: compName,
						Rule:        "missing-required-tags",
						Message:     fmt.Sprintf("Tag-manager missing required tags: %v", missingTags),
						Action:      "Add missing tags via FromValue or FromCompositeFieldPath",
					})
				}
			}
		}

		// Rule 3: Check tag propagation to child compositions
		childComps := v.getChildCompositions(comp)
		for _, child := range childComps {
			// Check if ANY variant of the child expects tags
			childVariants, exists := compositionMultiMap[child.Kind]
			if exists {
				for _, childComp := range childVariants {
					if v.compositionExpectsTags(childComp) {
						if !v.parentPassesTags(comp, child.Name) {
							result.MissingPropagation++
							result.Warnings = append(result.Warnings, TagWarning{
								File:        sourceFile,
								Composition: compName,
								Rule:        "tags-not-propagated",
								Message:     fmt.Sprintf("Child '%s' expects tags but parent doesn't propagate them", child.Kind),
								Action:      "Add patch: fromFieldPath: spec.parameters.tags → toFieldPath: spec.parameters.tags",
							})
						}
						break // Only warn once per child
					}
				}
			}
		}
	}

	// Calculate properly tagged
	result.ProperlyTagged = result.CloudCompositions - result.MissingTagManager - result.MissingPropagation
	if result.ProperlyTagged < 0 {
		result.ProperlyTagged = 0
	}

	return result
}

// BuildTagPropagationTree builds a tree showing tag propagation through compositions
func (v *TagValidator) BuildTagPropagationTree(compositions []*unstructured.Unstructured, rootKind string) *TagPropagationNode {
	// Build a MULTI-map of compositions by their composite type
	// This handles AWS/Azure variants of the same composition kind
	compositionMultiMap := make(map[string][]*unstructured.Unstructured)
	for _, comp := range compositions {
		if comp == nil || comp.GetKind() != "Composition" {
			continue
		}
		compositeType := v.getCompositeTypeRef(comp)
		if compositeType != "" {
			compositionMultiMap[compositeType] = append(compositionMultiMap[compositeType], comp)
		}
	}

	// Find root compositions (may have multiple variants)
	rootComps, exists := compositionMultiMap[rootKind]
	if !exists || len(rootComps) == 0 {
		return nil
	}

	return v.buildTreeNodeFromVariants(rootComps, compositionMultiMap, make(map[string]bool))
}

// buildTreeNodeFromVariants builds a tree node by merging all variants of a composition
func (v *TagValidator) buildTreeNodeFromVariants(compVariants []*unstructured.Unstructured, compositionMultiMap map[string][]*unstructured.Unstructured, visited map[string]bool) *TagPropagationNode {
	if len(compVariants) == 0 {
		return nil
	}

	// Use first variant for basic info
	firstComp := compVariants[0]
	compositeType := v.getCompositeTypeRef(firstComp)
	if visited[compositeType] {
		return nil // Prevent cycles
	}
	visited[compositeType] = true

	// Merge data from ALL variants
	hasTagManager := false
	receivesTags := false
	var allCloudResources []string
	var allChildren []ChildComposition
	childSeen := make(map[string]bool)

	for _, comp := range compVariants {
		// Merge tag-manager status (any variant having it counts)
		if v.hasTagManager(comp) {
			hasTagManager = true
		}

		// Merge receives tags (any variant expecting tags counts)
		if v.compositionExpectsTags(comp) {
			receivesTags = true
		}

		// Merge cloud resources from all variants
		cloudResources := v.getCloudResources(comp)
		for _, cr := range cloudResources {
			// Avoid duplicates
			found := false
			for _, existing := range allCloudResources {
				if existing == cr {
					found = true
					break
				}
			}
			if !found {
				allCloudResources = append(allCloudResources, cr)
			}
		}

		// Merge children from all variants (AWS and Azure may have different children)
		children := v.getChildCompositions(comp)
		for _, child := range children {
			if !childSeen[child.Kind] {
				childSeen[child.Kind] = true
				allChildren = append(allChildren, child)
			}
		}
	}

	node := &TagPropagationNode{
		Name:           firstComp.GetName(),
		Kind:           compositeType,
		File:           v.getSourceFile(firstComp),
		HasTagManager:  hasTagManager,
		ReceivesTags:   receivesTags,
		CloudResources: allCloudResources,
	}

	// Build children (check if ANY parent variant passes tags)
	for _, child := range allChildren {
		// Check if any parent variant passes tags to this child
		passesTags := false
		for _, comp := range compVariants {
			if v.parentPassesTags(comp, child.Name) {
				passesTags = true
				break
			}
		}
		node.PassesTags = node.PassesTags || passesTags

		childVariants, exists := compositionMultiMap[child.Kind]
		if exists {
			childNode := v.buildTreeNodeFromVariants(childVariants, compositionMultiMap, visited)
			if childNode != nil {
				childNode.ReceivesTags = passesTags
				node.Children = append(node.Children, childNode)
			}
		}
	}

	return node
}

// PrintTagPropagationTree prints the tag propagation tree
func (v *TagValidator) PrintTagPropagationTree(node *TagPropagationNode, indent string, isLast bool) string {
	if node == nil {
		return ""
	}

	var sb strings.Builder

	// Determine prefix
	prefix := indent
	if indent != "" {
		if isLast {
			prefix += "└─→ "
		} else {
			prefix += "├─→ "
		}
	}

	// Build status indicators
	status := ""
	if len(node.CloudResources) > 0 {
		if node.HasTagManager {
			if node.ReceivesTags || indent == "" {
				status = "✓"
			} else {
				status = "❌ (tags not received)"
			}
		} else {
			status = "❌ (no tag-manager)"
		}
	} else if len(node.Children) > 0 {
		if node.PassesTags || indent == "" {
			status = "✓"
		} else {
			status = "⚠ (doesn't pass tags)"
		}
	} else {
		status = "○"
	}

	sb.WriteString(fmt.Sprintf("%s%s %s\n", prefix, node.Kind, status))

	// Update indent for children
	newIndent := indent
	if indent != "" {
		if isLast {
			newIndent += "    "
		} else {
			newIndent += "│   "
		}
	} else {
		newIndent = "  "
	}

	// Print children
	for i, child := range node.Children {
		isLastChild := i == len(node.Children)-1
		sb.WriteString(v.PrintTagPropagationTree(child, newIndent, isLastChild))
	}

	return sb.String()
}

// Helper methods

func (v *TagValidator) shouldSkip(compName string) bool {
	for _, skip := range v.config.SkipCompositions {
		if compName == skip {
			return true
		}
	}
	return false
}

func (v *TagValidator) getSourceFile(comp *unstructured.Unstructured) string {
	annotations := comp.GetAnnotations()
	if annotations != nil {
		if source, ok := annotations["crossplane.io/source-file"]; ok {
			return source
		}
	}
	return comp.GetName()
}

func (v *TagValidator) getCompositeTypeRef(comp *unstructured.Unstructured) string {
	spec, ok := comp.Object["spec"].(map[string]interface{})
	if !ok {
		return ""
	}
	compositeTypeRef, ok := spec["compositeTypeRef"].(map[string]interface{})
	if !ok {
		return ""
	}
	kind, _ := compositeTypeRef["kind"].(string)
	return kind
}

func (v *TagValidator) getCloudResources(comp *unstructured.Unstructured) []string {
	var resources []string

	// Get resources from pipeline mode
	spec, ok := comp.Object["spec"].(map[string]interface{})
	if !ok {
		return resources
	}

	pipeline, ok := spec["pipeline"].([]interface{})
	if !ok {
		return resources
	}

	for _, step := range pipeline {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check for patch-and-transform resources
		resourcesList, ok := input["resources"].([]interface{})
		if !ok {
			continue
		}

		for _, res := range resourcesList {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			base, ok := resMap["base"].(map[string]interface{})
			if !ok {
				continue
			}

			apiVersion, _ := base["apiVersion"].(string)
			kind, _ := base["kind"].(string)

			// Check if it's a cloud resource
			for _, provider := range v.config.CloudProviders {
				if strings.Contains(apiVersion, provider) {
					resources = append(resources, fmt.Sprintf("%s/%s", apiVersion, kind))
					break
				}
			}
		}
	}

	return resources
}

func (v *TagValidator) hasTagManager(comp *unstructured.Unstructured) bool {
	spec, ok := comp.Object["spec"].(map[string]interface{})
	if !ok {
		return false
	}

	pipeline, ok := spec["pipeline"].([]interface{})
	if !ok {
		return false
	}

	for _, step := range pipeline {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		funcRef, ok := stepMap["functionRef"].(map[string]interface{})
		if !ok {
			continue
		}

		funcName, _ := funcRef["name"].(string)
		for _, tagManagerFunc := range v.config.TagManagerFunctions {
			if funcName == tagManagerFunc {
				return true
			}
		}
	}

	return false
}

func (v *TagValidator) getMissingRequiredTags(comp *unstructured.Unstructured) []string {
	var missing []string

	spec, ok := comp.Object["spec"].(map[string]interface{})
	if !ok {
		return v.config.RequiredTags
	}

	pipeline, ok := spec["pipeline"].([]interface{})
	if !ok {
		return v.config.RequiredTags
	}

	// Find tag-manager step
	for _, step := range pipeline {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		funcRef, ok := stepMap["functionRef"].(map[string]interface{})
		if !ok {
			continue
		}

		funcName, _ := funcRef["name"].(string)
		isTagManager := false
		for _, tmFunc := range v.config.TagManagerFunctions {
			if funcName == tmFunc {
				isTagManager = true
				break
			}
		}
		if !isTagManager {
			continue
		}

		// Parse tag-manager input
		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		foundTags := make(map[string]bool)
		hasFromCompositeFieldPath := false

		addTags, ok := input["addTags"].([]interface{})
		if !ok {
			continue
		}

		for _, addTag := range addTags {
			tagMap, ok := addTag.(map[string]interface{})
			if !ok {
				continue
			}

			tagType, _ := tagMap["type"].(string)

			if tagType == "FromValue" {
				// Static tags
				tags, ok := tagMap["tags"].(map[string]interface{})
				if ok {
					for tagKey := range tags {
						foundTags[tagKey] = true
					}
				}
			} else if tagType == "FromCompositeFieldPath" {
				// Dynamic tags from field path
				fromFieldPath, _ := tagMap["fromFieldPath"].(string)
				if fromFieldPath == "spec.parameters.tags" {
					hasFromCompositeFieldPath = true
				}
			}
		}

		// Check required tags
		for _, required := range v.config.RequiredTags {
			if !foundTags[required] && !hasFromCompositeFieldPath {
				missing = append(missing, required)
			}
		}

		break // Only check first tag-manager
	}

	return missing
}

// ChildComposition represents a child composition reference
type ChildComposition struct {
	Name string
	Kind string
}

func (v *TagValidator) getChildCompositions(comp *unstructured.Unstructured) []ChildComposition {
	var children []ChildComposition

	spec, ok := comp.Object["spec"].(map[string]interface{})
	if !ok {
		return children
	}

	pipeline, ok := spec["pipeline"].([]interface{})
	if !ok {
		return children
	}

	for _, step := range pipeline {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check for patch-and-transform resources
		resourcesList, ok := input["resources"].([]interface{})
		if !ok {
			continue
		}

		for _, res := range resourcesList {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			name, _ := resMap["name"].(string)

			base, ok := resMap["base"].(map[string]interface{})
			if !ok {
				continue
			}

			apiVersion, _ := base["apiVersion"].(string)
			kind, _ := base["kind"].(string)

			// Check if it's a composition reference (custom API group, not cloud provider)
			if !v.isCloudResource(apiVersion) && strings.Contains(apiVersion, "/") {
				// Likely a nested composition
				children = append(children, ChildComposition{
					Name: name,
					Kind: kind,
				})
			}
		}
	}

	return children
}

func (v *TagValidator) isCloudResource(apiVersion string) bool {
	for _, provider := range v.config.CloudProviders {
		if strings.Contains(apiVersion, provider) {
			return true
		}
	}
	// Also check for Kubernetes core resources
	if strings.HasPrefix(apiVersion, "kubernetes.crossplane.io") ||
		strings.HasPrefix(apiVersion, "helm.crossplane.io") ||
		apiVersion == "v1" ||
		strings.HasPrefix(apiVersion, "apps/") ||
		strings.HasPrefix(apiVersion, "batch/") {
		return false
	}
	return false
}

func (v *TagValidator) compositionExpectsTags(comp *unstructured.Unstructured) bool {
	// Check if the composition's tag-manager uses FromCompositeFieldPath for tags
	spec, ok := comp.Object["spec"].(map[string]interface{})
	if !ok {
		return false
	}

	pipeline, ok := spec["pipeline"].([]interface{})
	if !ok {
		return false
	}

	for _, step := range pipeline {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		funcRef, ok := stepMap["functionRef"].(map[string]interface{})
		if !ok {
			continue
		}

		funcName, _ := funcRef["name"].(string)
		isTagManager := false
		for _, tmFunc := range v.config.TagManagerFunctions {
			if funcName == tmFunc {
				isTagManager = true
				break
			}
		}
		if !isTagManager {
			continue
		}

		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		addTags, ok := input["addTags"].([]interface{})
		if !ok {
			continue
		}

		for _, addTag := range addTags {
			tagMap, ok := addTag.(map[string]interface{})
			if !ok {
				continue
			}

			tagType, _ := tagMap["type"].(string)
			if tagType == "FromCompositeFieldPath" {
				fromFieldPath, _ := tagMap["fromFieldPath"].(string)
				if fromFieldPath == "spec.parameters.tags" {
					return true
				}
			}
		}
	}

	return false
}

func (v *TagValidator) parentPassesTags(comp *unstructured.Unstructured, childResourceName string) bool {
	spec, ok := comp.Object["spec"].(map[string]interface{})
	if !ok {
		return false
	}

	pipeline, ok := spec["pipeline"].([]interface{})
	if !ok {
		return false
	}

	for _, step := range pipeline {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		resourcesList, ok := input["resources"].([]interface{})
		if !ok {
			continue
		}

		for _, res := range resourcesList {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			name, _ := resMap["name"].(string)
			if name != childResourceName {
				continue
			}

			// Check patches for this resource
			patches, ok := resMap["patches"].([]interface{})
			if !ok {
				continue
			}

			for _, patch := range patches {
				patchMap, ok := patch.(map[string]interface{})
				if !ok {
					continue
				}

				fromFieldPath, _ := patchMap["fromFieldPath"].(string)
				toFieldPath, _ := patchMap["toFieldPath"].(string)

				if fromFieldPath == "spec.parameters.tags" && toFieldPath == "spec.parameters.tags" {
					return true
				}
			}
		}
	}

	return false
}

// PrintTagValidationResults prints tag validation results to the output
func PrintTagValidationResults(result TagValidationResult, out interface{ Write([]byte) (int, error) }, showAnalysis bool) error {
	// Skip if no cloud compositions or no issues
	if result.CloudCompositions == 0 && len(result.Warnings) == 0 && len(result.Errors) == 0 {
		return nil
	}

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "🏷️  Tag Validation Results\n")
	fmt.Fprintf(out, "══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "\n")

	// Print warnings
	for _, warning := range result.Warnings {
		fmt.Fprintf(out, "[!] %s\n", warning.File)
		fmt.Fprintf(out, "    Rule: %s\n", warning.Rule)
		fmt.Fprintf(out, "    %s\n", warning.Message)
		if len(warning.Affected) > 0 {
			fmt.Fprintf(out, "    Affected: %v\n", warning.Affected)
		}
		fmt.Fprintf(out, "    → Action: %s\n", warning.Action)
		fmt.Fprintf(out, "\n")
	}

	// Print errors
	for _, err := range result.Errors {
		fmt.Fprintf(out, "[x] %s\n", err.File)
		fmt.Fprintf(out, "    Rule: %s\n", err.Rule)
		fmt.Fprintf(out, "    %s\n", err.Message)
		fmt.Fprintf(out, "\n")
	}

	// Print summary
	fmt.Fprintf(out, "══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "Tag Validation Summary:\n")
	fmt.Fprintf(out, "  Compositions checked: %d\n", result.CompositionsChecked)
	fmt.Fprintf(out, "  With cloud resources: %d\n", result.CloudCompositions)

	if result.CloudCompositions > 0 {
		fmt.Fprintf(out, "  Properly tagged: %d\n", result.ProperlyTagged)
		fmt.Fprintf(out, "  Missing tag-manager: %d\n", result.MissingTagManager)
		fmt.Fprintf(out, "  Missing tag propagation: %d\n", result.MissingPropagation)
	}

	if len(result.Warnings) == 0 && len(result.Errors) == 0 {
		fmt.Fprintf(out, "\n✓ All cloud resources properly configured for tagging!\n")
	}

	fmt.Fprintf(out, "\n")

	return nil
}
