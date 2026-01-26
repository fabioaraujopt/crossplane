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
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// CompositionSelectorValidator validates that compositionSelector.matchLabels
// in child resources actually match existing compositions.
type CompositionSelectorValidator struct {
	compositions map[string]*ParsedComposition // name -> composition
	xrdKinds     map[string]bool               // tracks all XRD kinds

	// Track which compositions are selected (for dead code detection)
	selectedCompositions map[string]bool

	// XRD schemas for enum lookup (kind -> schema)
	xrdSchemas map[string]*extv1.JSONSchemaProps

	// Map of compositeTypeRef.kind -> list of compositions
	compositionsByKind map[string][]*ParsedComposition
}

// NewCompositionSelectorValidator creates a new validator.
func NewCompositionSelectorValidator(compositions []*ParsedComposition) *CompositionSelectorValidator {
	v := &CompositionSelectorValidator{
		compositions:         make(map[string]*ParsedComposition),
		xrdKinds:             make(map[string]bool),
		selectedCompositions: make(map[string]bool),
		xrdSchemas:           make(map[string]*extv1.JSONSchemaProps),
		compositionsByKind:   make(map[string][]*ParsedComposition),
	}

	for _, comp := range compositions {
		v.compositions[comp.Name] = comp
		v.xrdKinds[comp.CompositeTypeRef.Kind] = true
		v.compositionsByKind[comp.CompositeTypeRef.Kind] = append(
			v.compositionsByKind[comp.CompositeTypeRef.Kind], comp,
		)
	}

	return v
}

// SetXRDSchemas sets XRD schemas for enum value lookup during patch tracing.
func (v *CompositionSelectorValidator) SetXRDSchemas(xrds []*unstructured.Unstructured) {
	for _, xrd := range xrds {
		kind, _, _ := unstructured.NestedString(xrd.Object, "spec", "names", "kind")
		if kind == "" {
			continue
		}

		// Get the schema from the first version
		versions, _, _ := unstructured.NestedSlice(xrd.Object, "spec", "versions")
		for _, ver := range versions {
			verMap, ok := ver.(map[string]interface{})
			if !ok {
				continue
			}

			schemaMap, _, _ := unstructured.NestedMap(verMap, "schema", "openAPIV3Schema")
			if schemaMap == nil {
				continue
			}

			// Convert to JSONSchemaProps
			schemaBytes, err := json.Marshal(schemaMap)
			if err != nil {
				continue
			}

			var schema extv1.JSONSchemaProps
			if err := json.Unmarshal(schemaBytes, &schema); err != nil {
				continue
			}

			v.xrdSchemas[kind] = &schema
			break // Use first version
		}
	}
}

// CompositionSelectorError represents a composition selector validation error.
type CompositionSelectorError struct {
	CompositionName string
	ResourceName    string
	TargetKind      string
	Selector        map[string]string
	Message         string
	Severity        string // "error" or "warning"
}

func (e CompositionSelectorError) Error() string {
	labels := formatLabels(e.Selector)
	return fmt.Sprintf("composition '%s' resource '%s': %s (selector: %s)",
		e.CompositionName, e.ResourceName, e.Message, labels)
}

// Validate performs composition selector validation.
func (v *CompositionSelectorValidator) Validate() []CompositionSelectorError {
	var errors []CompositionSelectorError

	// First pass: collect all dynamic selector patches
	// Map: parent composition -> child kind -> label key -> possible values (from enum or patch source)
	dynamicSelectors := v.collectDynamicSelectors()

	// Check each composition's resources for selectors
	for _, comp := range v.compositions {
		for _, res := range comp.Resources {
			// Check if this resource is a child XR (has a selector)
			// Note: Even empty selectors {} should be validated (they won't match anything)
			if res.CompositionSelector != nil {
				kind := res.Base.GetKind()

				// Check if there are patches that dynamically set selector labels
				dynamicLabels := v.getDynamicSelectorLabels(comp.Name, res.Name, kind, res.Patches)

				// Merge static and dynamic selectors
				effectiveSelector := make(map[string]string)
				for k, val := range res.CompositionSelector {
					effectiveSelector[k] = val
				}

				// For dynamically-patched labels, we need to verify compositions exist
				// with each possible enum value
				hasDynamicLabels := len(dynamicLabels) > 0

				if hasDynamicLabels {
					// Validate that compositions exist for ALL possible dynamic values
					for labelKey, possibleValues := range dynamicLabels {
						if len(possibleValues) == 0 {
							// Couldn't determine possible values - skip warning
							continue
						}

						for _, labelValue := range possibleValues {
							testSelector := make(map[string]string)
							for k, val := range effectiveSelector {
								if k != labelKey {
									testSelector[k] = val
								}
							}
							testSelector[labelKey] = labelValue

							matchingComps := v.findMatchingCompositions(kind, testSelector)
							if len(matchingComps) == 0 {
								errors = append(errors, CompositionSelectorError{
									CompositionName: comp.Name,
									ResourceName:    res.Name,
									TargetKind:      kind,
									Selector:        testSelector,
									Message:         fmt.Sprintf("no composition of kind '%s' matches dynamic selector value '%s=%s'", kind, labelKey, labelValue),
									Severity:        "error",
								})
							} else {
								// Mark as selected
								for _, matchedComp := range matchingComps {
									v.selectedCompositions[matchedComp] = true
								}
							}
						}
					}
				} else {
					// Static selector - validate as before
					matchingComps := v.findMatchingCompositions(kind, res.CompositionSelector)

					if len(matchingComps) == 0 {
						errors = append(errors, CompositionSelectorError{
							CompositionName: comp.Name,
							ResourceName:    res.Name,
							TargetKind:      kind,
							Selector:        res.CompositionSelector,
							Message:         fmt.Sprintf("no composition of kind '%s' matches selector", kind),
							Severity:        "error",
						})
					} else {
						// Mark these compositions as selected (used)
						for _, matchedComp := range matchingComps {
							v.selectedCompositions[matchedComp] = true
						}
					}
				}
			}
		}
	}

	// Also mark compositions as selected via dynamic selectors from parent analysis
	for parentName, kindMap := range dynamicSelectors {
		for childKind, labelMap := range kindMap {
			for labelKey, possibleValues := range labelMap {
				for _, labelValue := range possibleValues {
					testSelector := map[string]string{labelKey: labelValue}
					matchingComps := v.findMatchingCompositions(childKind, testSelector)
					for _, matchedComp := range matchingComps {
						v.selectedCompositions[matchedComp] = true
					}
				}
				_ = parentName // suppress unused warning
			}
		}
	}

	// Detect unused compositions (with labels but never selected)
	unusedComps := v.detectUnusedCompositions()
	for _, compName := range unusedComps {
		comp := v.compositions[compName]
		errors = append(errors, CompositionSelectorError{
			CompositionName: compName,
			ResourceName:    "",
			TargetKind:      comp.CompositeTypeRef.Kind,
			Selector:        comp.Labels,
			Message:         "composition has labels but is never selected by any compositionSelector",
			Severity:        "warning",
		})
	}

	return errors
}

// collectDynamicSelectors collects all patches that dynamically set compositionSelector labels.
// Returns: parentComp -> childKind -> labelKey -> []possibleValues
func (v *CompositionSelectorValidator) collectDynamicSelectors() map[string]map[string]map[string][]string {
	result := make(map[string]map[string]map[string][]string)

	for _, comp := range v.compositions {
		for _, res := range comp.Resources {
			if res.Base == nil {
				continue
			}
			childKind := res.Base.GetKind()

			for _, patch := range res.Patches {
				// Check if patch writes to compositionSelector.matchLabels.*
				labelKey := v.extractSelectorLabelKey(patch.ToFieldPath)
				if labelKey == "" {
					continue
				}

				// Get possible values from patch source
				possibleValues := v.getPossibleValuesFromPatch(comp, patch)

				// Store the dynamic selector
				if result[comp.Name] == nil {
					result[comp.Name] = make(map[string]map[string][]string)
				}
				if result[comp.Name][childKind] == nil {
					result[comp.Name][childKind] = make(map[string][]string)
				}
				result[comp.Name][childKind][labelKey] = append(
					result[comp.Name][childKind][labelKey], possibleValues...,
				)
			}
		}
	}

	return result
}

// getDynamicSelectorLabels returns labels that are dynamically patched for a resource.
// Returns: labelKey -> []possibleValues
func (v *CompositionSelectorValidator) getDynamicSelectorLabels(compName, resName, childKind string, patches []Patch) map[string][]string {
	result := make(map[string][]string)

	comp := v.compositions[compName]
	if comp == nil {
		return result
	}

	for _, patch := range patches {
		labelKey := v.extractSelectorLabelKey(patch.ToFieldPath)
		if labelKey == "" {
			continue
		}

		possibleValues := v.getPossibleValuesFromPatch(comp, patch)
		result[labelKey] = append(result[labelKey], possibleValues...)
	}

	return result
}

// extractSelectorLabelKey extracts the label key from a toFieldPath that targets compositionSelector.
// Examples:
//   - "spec.compositionSelector.matchLabels.provider" -> "provider"
//   - "spec.crossplane.compositionSelector.matchLabels.provider" -> "provider"
func (v *CompositionSelectorValidator) extractSelectorLabelKey(toFieldPath string) string {
	patterns := []string{
		"spec.compositionSelector.matchLabels.",
		"spec.crossplane.compositionSelector.matchLabels.",
	}

	for _, pattern := range patterns {
		if strings.HasPrefix(toFieldPath, pattern) {
			return strings.TrimPrefix(toFieldPath, pattern)
		}
	}

	return ""
}

// getPossibleValuesFromPatch determines the possible values a patch can produce.
// It traces the fromFieldPath to the XRD schema and extracts enum values.
func (v *CompositionSelectorValidator) getPossibleValuesFromPatch(comp *ParsedComposition, patch Patch) []string {
	// For FromCompositeFieldPath patches, trace to the XRD schema
	if patch.Type == PatchTypeFromCompositeFieldPath || patch.Type == "" {
		return v.getEnumValuesFromFieldPath(comp.CompositeTypeRef.Kind, patch.FromFieldPath, patch.Transforms)
	}

	// For CombineFromComposite, check if all variables come from enum fields
	if patch.Type == PatchTypeCombineFromComposite && patch.Combine != nil {
		// If only one variable, use its enum values
		if len(patch.Combine.Variables) == 1 {
			return v.getEnumValuesFromFieldPath(comp.CompositeTypeRef.Kind, patch.Combine.Variables[0].FromFieldPath, patch.Transforms)
		}
	}

	return nil
}

// getEnumValuesFromFieldPath looks up the enum values for a field path in the XRD schema.
func (v *CompositionSelectorValidator) getEnumValuesFromFieldPath(kind, fieldPath string, transforms []Transform) []string {
	schema := v.xrdSchemas[kind]
	if schema == nil {
		return nil
	}

	// Navigate to the field in the schema
	fieldSchema := v.navigateToField(schema, fieldPath)
	if fieldSchema == nil {
		return nil
	}

	// Extract enum values
	var values []string
	for _, enumVal := range fieldSchema.Enum {
		var val string
		if err := json.Unmarshal(enumVal.Raw, &val); err == nil {
			// Apply transforms if any
			transformed := v.applyTransforms(val, transforms)
			values = append(values, transformed)
		}
	}

	return values
}

// navigateToField navigates through the schema to find a field.
func (v *CompositionSelectorValidator) navigateToField(schema *extv1.JSONSchemaProps, fieldPath string) *extv1.JSONSchemaProps {
	if schema == nil || fieldPath == "" {
		return schema
	}

	parts := strings.Split(fieldPath, ".")
	current := schema

	for _, part := range parts {
		// Handle array notation like "items[0]"
		if strings.Contains(part, "[") {
			basePart := strings.Split(part, "[")[0]
			if current.Properties == nil {
				return nil
			}
			prop, ok := current.Properties[basePart]
			if !ok {
				return nil
			}
			// For arrays, return the items schema
			if prop.Items != nil && prop.Items.Schema != nil {
				current = prop.Items.Schema
			} else {
				current = &prop
			}
			continue
		}

		if current.Properties == nil {
			return nil
		}

		prop, ok := current.Properties[part]
		if !ok {
			return nil
		}
		current = &prop
	}

	return current
}

// applyTransforms applies patch transforms to a value.
// For now, handles simple map transforms.
func (v *CompositionSelectorValidator) applyTransforms(value string, transforms []Transform) string {
	result := value

	for _, transform := range transforms {
		if transform.Map != nil {
			if mapped, ok := transform.Map[result]; ok {
				result = mapped
			}
		}
		// Add more transform handling as needed
	}

	return result
}

// findMatchingCompositions finds all compositions of the given kind that match the selector.
func (v *CompositionSelectorValidator) findMatchingCompositions(targetKind string, selector map[string]string) []string {
	var matches []string

	for name, comp := range v.compositions {
		// Check if composition is for the target kind
		if comp.CompositeTypeRef.Kind != targetKind {
			continue
		}

		// Check if all selector labels match composition labels
		if labelsMatch(selector, comp.Labels) {
			matches = append(matches, name)
		}
	}

	return matches
}

// labelsMatch checks if all selector labels exist in target labels with matching values.
func labelsMatch(selector, target map[string]string) bool {
	if len(selector) == 0 {
		// Empty selector matches nothing (must be explicit)
		return false
	}

	for key, value := range selector {
		if target[key] != value {
			return false
		}
	}
	return true
}

// detectUnusedCompositions finds compositions with labels that are never selected.
func (v *CompositionSelectorValidator) detectUnusedCompositions() []string {
	var unused []string

	// First, find all kinds that are referenced as child XRs
	referencedKinds := make(map[string]bool)
	for _, comp := range v.compositions {
		for _, res := range comp.Resources {
			if res.Base != nil {
				referencedKinds[res.Base.GetKind()] = true
			}
		}
	}

	for name, comp := range v.compositions {
		// Skip compositions without labels (can't be selected anyway)
		if len(comp.Labels) == 0 {
			continue
		}

		// Skip ROOT compositions (entry points) - their kind is not referenced by any other composition
		// These are created directly by users, not selected by compositionSelector
		if !referencedKinds[comp.CompositeTypeRef.Kind] {
			continue
		}

		// If composition was never marked as selected, it's unused
		if !v.selectedCompositions[name] {
			unused = append(unused, name)
		}
	}

	// Sort for deterministic output
	sort.Strings(unused)
	return unused
}

// formatLabels formats a label map for display.
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}

	var pairs []string
	for k, v := range labels {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(pairs)
	return "{" + strings.Join(pairs, ", ") + "}"
}
