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
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ResourceSelectorValidator validates resource selectors (like subnetIdSelector)
// to detect ambiguous selectors that could match resources from multiple stamps/compositions.
type ResourceSelectorValidator struct {
	compositions []*ParsedComposition

	// Maps serialized label sets to compositions that CREATE resources with those labels
	// Key: sorted label key-values, Value: list of creation info
	labelCreators map[string][]LabelCreationInfo

	// All selectors found in compositions
	selectors []SelectorInfo

	// Track composition hierarchy for sibling detection
	compositionHierarchy map[string]string // compositionName -> parentXRKind
}

// LabelCreationInfo tracks where labels are created.
type LabelCreationInfo struct {
	CompositionName string
	ResourceName    string
	ResourceKind    string
	Labels          map[string]string
	IsDynamic       bool   // Labels are patched dynamically
	DynamicKey      string // The dynamic label key (if patched)
	SourceFile      string
	SourceLine      int
}

// SelectorInfo tracks selector usage.
type SelectorInfo struct {
	CompositionName     string
	ResourceName        string
	ResourceKind        string
	SelectorPath        string            // e.g., "spec.forProvider.subnetIdSelector"
	MatchLabels         map[string]string // Static labels
	HasControllerRef    bool
	IsDynamic           bool              // Selector is patched dynamically
	DynamicLabels       map[string]string // Labels added via patches
	SourceFile          string
	SourceLine          int
}

// ResourceSelectorError represents a resource selector validation error.
type ResourceSelectorError struct {
	CompositionName string
	ResourceName    string
	SelectorPath    string
	MatchLabels     map[string]string
	Message         string
	Severity        string // "error" or "warning"
	Recommendation  string
	Creators        []string // Compositions that create matching resources
}

func (e ResourceSelectorError) Error() string {
	labels := formatLabels(e.MatchLabels)
	msg := fmt.Sprintf("composition '%s' resource '%s' path '%s': %s (selector: %s)",
		e.CompositionName, e.ResourceName, e.SelectorPath, e.Message, labels)
	if e.Recommendation != "" {
		msg += fmt.Sprintf("\n     Recommendation: %s", e.Recommendation)
	}
	return msg
}

// NewResourceSelectorValidator creates a new validator.
func NewResourceSelectorValidator(compositions []*ParsedComposition) *ResourceSelectorValidator {
	v := &ResourceSelectorValidator{
		compositions:         compositions,
		labelCreators:        make(map[string][]LabelCreationInfo),
		selectors:            make([]SelectorInfo, 0),
		compositionHierarchy: make(map[string]string),
	}

	// Parse all compositions to extract labels and selectors
	for _, comp := range compositions {
		v.parseComposition(comp)
	}

	return v
}

// parseComposition extracts label creations and selector usages from a composition.
func (v *ResourceSelectorValidator) parseComposition(comp *ParsedComposition) {
	// Track this composition's parent type
	v.compositionHierarchy[comp.Name] = comp.CompositeTypeRef.Kind

	for _, res := range comp.Resources {
		if res.Base == nil {
			continue
		}

		// 1. Extract labels from base.metadata.labels
		v.extractLabels(comp, res)

		// 2. Extract selectors from spec.forProvider.*Selector
		v.extractSelectors(comp, res)
	}

	// 3. Process patches to find dynamic labels and selectors
	v.processPatchesForLabelsAndSelectors(comp)
}

// extractLabels extracts labels from base.metadata.labels.
func (v *ResourceSelectorValidator) extractLabels(comp *ParsedComposition, res ComposedResource) {
	labels, found, err := unstructured.NestedStringMap(res.Base.Object, "metadata", "labels")
	if err != nil || !found || len(labels) == 0 {
		return
	}

	info := LabelCreationInfo{
		CompositionName: comp.Name,
		ResourceName:    res.Name,
		ResourceKind:    res.Base.GetKind(),
		Labels:          labels,
		SourceFile:      comp.SourceFile,
		SourceLine:      comp.SourceLine,
	}

	// Create a key from the labels (sorted for consistency)
	key := serializeLabels(labels)
	v.labelCreators[key] = append(v.labelCreators[key], info)
}

// extractSelectors extracts *Selector fields from spec.forProvider.
func (v *ResourceSelectorValidator) extractSelectors(comp *ParsedComposition, res ComposedResource) {
	// Look for selectors in spec.forProvider.*Selector and spec.forProvider.*.*Selector
	spec, found, _ := unstructured.NestedMap(res.Base.Object, "spec")
	if !found {
		return
	}

	forProvider, found, _ := unstructured.NestedMap(spec, "forProvider")
	if !found {
		return
	}

	v.extractSelectorsFromMap(comp, res, forProvider, "spec.forProvider")

	// Also check nested structures like vpcConfig
	for key, val := range forProvider {
		if nested, ok := val.(map[string]interface{}); ok {
			v.extractSelectorsFromMap(comp, res, nested, "spec.forProvider."+key)
		}
	}
}

// extractSelectorsFromMap extracts selectors from a map.
func (v *ResourceSelectorValidator) extractSelectorsFromMap(comp *ParsedComposition, res ComposedResource, m map[string]interface{}, path string) {
	for key, val := range m {
		if !strings.HasSuffix(key, "Selector") {
			continue
		}

		selectorMap, ok := val.(map[string]interface{})
		if !ok {
			continue
		}

		selectorPath := path + "." + key

		// Check for matchControllerRef
		hasControllerRef := false
		if mcr, ok := selectorMap["matchControllerRef"].(bool); ok {
			hasControllerRef = mcr
		}

		// Extract matchLabels
		matchLabels := make(map[string]string)
		if ml, ok := selectorMap["matchLabels"].(map[string]interface{}); ok {
			for k, v := range ml {
				if strV, ok := v.(string); ok {
					matchLabels[k] = strV
				}
			}
		}

		// Skip if no matchLabels (selector might use only matchControllerRef)
		if len(matchLabels) == 0 && !hasControllerRef {
			continue
		}

		info := SelectorInfo{
			CompositionName:  comp.Name,
			ResourceName:     res.Name,
			ResourceKind:     res.Base.GetKind(),
			SelectorPath:     selectorPath,
			MatchLabels:      matchLabels,
			HasControllerRef: hasControllerRef,
			DynamicLabels:    make(map[string]string),
			SourceFile:       comp.SourceFile,
			SourceLine:       comp.SourceLine,
		}

		v.selectors = append(v.selectors, info)
	}
}

// processPatchesForLabelsAndSelectors finds patches that create/modify labels and selectors.
func (v *ResourceSelectorValidator) processPatchesForLabelsAndSelectors(comp *ParsedComposition) {
	for _, patchInfo := range comp.AllPatches {
		toPath := patchInfo.Patch.ToFieldPath
		if toPath == "" {
			continue
		}

		// Check if patch targets metadata.labels
		if strings.Contains(toPath, "metadata.labels") {
			v.markDynamicLabel(comp.Name, patchInfo.ResourceName, toPath)
		}

		// Check if patch targets a selector's matchLabels
		if strings.Contains(toPath, "Selector.matchLabels") || strings.Contains(toPath, "Selector") && strings.Contains(toPath, "matchLabels") {
			v.markDynamicSelector(comp.Name, patchInfo.ResourceName, toPath, patchInfo.Patch.FromFieldPath)
		}
	}
}

// markDynamicLabel marks a label as dynamically created.
func (v *ResourceSelectorValidator) markDynamicLabel(compName, resName, toPath string) {
	// Extract the label key being patched
	// e.g., "metadata.labels[\"stamp-name\"]" or "metadata.labels.stamp-name"
	labelKey := extractLabelKey(toPath)

	for key, creators := range v.labelCreators {
		for i := range creators {
			if creators[i].CompositionName == compName && creators[i].ResourceName == resName {
				v.labelCreators[key][i].IsDynamic = true
				v.labelCreators[key][i].DynamicKey = labelKey
			}
		}
	}
}

// markDynamicSelector marks a selector as having dynamic labels.
func (v *ResourceSelectorValidator) markDynamicSelector(compName, resName, toPath, fromPath string) {
	// Extract the label key being patched
	labelKey := extractSelectorLabelKey(toPath)

	for i := range v.selectors {
		if v.selectors[i].CompositionName == compName && v.selectors[i].ResourceName == resName {
			if strings.Contains(toPath, v.selectors[i].SelectorPath) {
				v.selectors[i].IsDynamic = true
				if labelKey != "" {
					// Track that this selector will have a dynamic label
					v.selectors[i].DynamicLabels[labelKey] = fromPath
				}
			}
		}
	}
}

// Validate performs resource selector validation.
func (v *ResourceSelectorValidator) Validate() []ResourceSelectorError {
	var errors []ResourceSelectorError

	// Check each selector
	for _, sel := range v.selectors {
		// Skip selectors that use matchControllerRef AND have dynamic labels
		// These are likely properly isolated
		if sel.HasControllerRef && sel.IsDynamic {
			continue
		}

		// Find all label creators that match this selector's labels
		matchingCreators := v.findMatchingCreators(sel)

		// Case 1: No matching creators at all (orphaned selector)
		if len(matchingCreators) == 0 && len(sel.MatchLabels) > 0 {
			// Check if this is a known external resource type (like subnets that might come from Observe)
			if !v.isExternalResourceSelector(sel) {
				errors = append(errors, ResourceSelectorError{
					CompositionName: sel.CompositionName,
					ResourceName:    sel.ResourceName,
					SelectorPath:    sel.SelectorPath,
					MatchLabels:     sel.MatchLabels,
					Message:         "selector uses labels that are not created by any composition",
					Severity:        "warning",
					Recommendation:  "Verify these labels exist on resources or add label creation to a composition",
				})
			}
			continue
		}

		// Case 2: Multiple creators without isolation
		if len(matchingCreators) > 0 && !sel.HasControllerRef {
			// Check if selectors have unique identifying labels
			if !v.hasUniqueIdentifier(sel) {
				// Get unique composition names that create matching labels
				creatorComps := v.getUniqueCreatorCompositions(matchingCreators)

				// Check if any creator is reusable (could have multiple instances)
				if v.isReusableComposition(creatorComps) || len(creatorComps) > 1 {
					severity := "warning"
					message := fmt.Sprintf("selector could match resources from multiple stamps/instances. Created by: %s",
						strings.Join(creatorComps, ", "))

					recommendation := "Add 'matchControllerRef: true' if selecting from same composition, " +
						"or add a unique identifying label (e.g., 'stamp-name') to both the resource and selector"

					// If creators are siblings, matchControllerRef won't work
					if v.areSiblingCompositions(sel.CompositionName, creatorComps) {
						message += " (siblings - matchControllerRef won't work)"
						recommendation = "Add a unique identifying label (e.g., 'stamp-name') patched from spec.parameters " +
							"to both the created resources and this selector"
					}

					errors = append(errors, ResourceSelectorError{
						CompositionName: sel.CompositionName,
						ResourceName:    sel.ResourceName,
						SelectorPath:    sel.SelectorPath,
						MatchLabels:     sel.MatchLabels,
						Message:         message,
						Severity:        severity,
						Recommendation:  recommendation,
						Creators:        creatorComps,
					})
				}
			}
		}
	}

	return errors
}

// findMatchingCreators finds all label creators that would match a selector.
func (v *ResourceSelectorValidator) findMatchingCreators(sel SelectorInfo) []LabelCreationInfo {
	var matches []LabelCreationInfo

	for _, creators := range v.labelCreators {
		for _, creator := range creators {
			// Check if all selector labels match creator labels
			if labelsSubset(sel.MatchLabels, creator.Labels) {
				matches = append(matches, creator)
			}
		}
	}

	return matches
}

// labelsSubset checks if all labels in subset exist in superset with matching values.
func labelsSubset(subset, superset map[string]string) bool {
	for k, v := range subset {
		if superset[k] != v {
			return false
		}
	}
	return true
}

// hasUniqueIdentifier checks if a selector has a unique identifying label.
var uniqueIdentifyingLabels = []string{
	"stamp-name",
	"cluster-name",
	"stamp",
	"platform-name",
	"crossplane.io/claim-name",
	"crossplane.io/composite",
	"tenant-name",
}

func (v *ResourceSelectorValidator) hasUniqueIdentifier(sel SelectorInfo) bool {
	// Check static labels
	for _, uniqueKey := range uniqueIdentifyingLabels {
		if _, exists := sel.MatchLabels[uniqueKey]; exists {
			return true
		}
	}

	// Check dynamic labels
	for labelKey := range sel.DynamicLabels {
		for _, uniqueKey := range uniqueIdentifyingLabels {
			if labelKey == uniqueKey {
				return true
			}
		}
	}

	return false
}

// getUniqueCreatorCompositions returns unique composition names from creators.
func (v *ResourceSelectorValidator) getUniqueCreatorCompositions(creators []LabelCreationInfo) []string {
	seen := make(map[string]bool)
	var result []string

	for _, c := range creators {
		if !seen[c.CompositionName] {
			seen[c.CompositionName] = true
			result = append(result, c.CompositionName)
		}
	}

	sort.Strings(result)
	return result
}

// isReusableComposition checks if a composition could be instantiated multiple times.
// In Crossplane, all compositions can be reused when their XRs are created multiple times.
func (v *ResourceSelectorValidator) isReusableComposition(compositionNames []string) bool {
	// All compositions are potentially reusable (multiple XR instances can use them)
	return len(compositionNames) > 0
}

// areSiblingCompositions checks if the selector's composition and any creator are siblings.
func (v *ResourceSelectorValidator) areSiblingCompositions(selectorComp string, creatorComps []string) bool {
	selectorParent, ok := v.compositionHierarchy[selectorComp]
	if !ok {
		return false
	}

	for _, creator := range creatorComps {
		creatorParent, ok := v.compositionHierarchy[creator]
		if !ok {
			continue
		}

		// Same parent means they're siblings
		// e.g., both are children of StampCommonV2
		if selectorParent == creatorParent && selectorComp != creator {
			return true
		}
	}

	return false
}

// isExternalResourceSelector checks if this selector is for external resources.
func (v *ResourceSelectorValidator) isExternalResourceSelector(sel SelectorInfo) bool {
	// Some selectors reference resources that might be created outside Crossplane
	// or come from Observe-only resources
	externalPatterns := []string{
		"securityGroupIdSelector",
		"roleArnSelector",
		"certificateArnSelector",
	}

	for _, pattern := range externalPatterns {
		if strings.Contains(sel.SelectorPath, pattern) {
			return true
		}
	}

	return false
}

// serializeLabels creates a consistent string key from labels.
func serializeLabels(labels map[string]string) string {
	var pairs []string
	for k, v := range labels {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

// extractLabelKey extracts the label key from a patch toFieldPath.
// e.g., "metadata.labels[\"stamp-name\"]" -> "stamp-name"
// e.g., "metadata.labels.stamp-name" -> "stamp-name"
func extractLabelKey(path string) string {
	if idx := strings.Index(path, "[\""); idx != -1 {
		end := strings.Index(path[idx:], "\"]")
		if end != -1 {
			return path[idx+2 : idx+end]
		}
	}

	parts := strings.Split(path, ".")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		// Remove any bracket notation
		if idx := strings.Index(last, "["); idx != -1 {
			return last[:idx]
		}
		return last
	}
	return ""
}

// extractSelectorLabelKey extracts the label key from a selector patch path.
// e.g., "spec.forProvider.subnetIdSelector.matchLabels[\"stamp-name\"]" -> "stamp-name"
func extractSelectorLabelKey(path string) string {
	if !strings.Contains(path, "matchLabels") {
		return ""
	}

	// Find the part after matchLabels
	idx := strings.Index(path, "matchLabels")
	if idx == -1 {
		return ""
	}

	remaining := path[idx+len("matchLabels"):]
	return extractLabelKey("." + remaining)
}

// GetLabelCreators returns all label creation info (for testing).
func (v *ResourceSelectorValidator) GetLabelCreators() map[string][]LabelCreationInfo {
	return v.labelCreators
}

// GetSelectors returns all selector info (for testing).
func (v *ResourceSelectorValidator) GetSelectors() []SelectorInfo {
	return v.selectors
}
