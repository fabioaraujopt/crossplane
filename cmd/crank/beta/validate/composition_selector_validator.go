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
)

// CompositionSelectorValidator validates that compositionSelector.matchLabels
// in child resources actually match existing compositions.
type CompositionSelectorValidator struct {
	compositions map[string]*ParsedComposition // name -> composition
	xrdKinds     map[string]bool               // tracks all XRD kinds

	// Track which compositions are selected (for dead code detection)
	selectedCompositions map[string]bool
}

// NewCompositionSelectorValidator creates a new validator.
func NewCompositionSelectorValidator(compositions []*ParsedComposition) *CompositionSelectorValidator {
	v := &CompositionSelectorValidator{
		compositions:         make(map[string]*ParsedComposition),
		xrdKinds:             make(map[string]bool),
		selectedCompositions: make(map[string]bool),
	}

	for _, comp := range compositions {
		v.compositions[comp.Name] = comp
		v.xrdKinds[comp.CompositeTypeRef.Kind] = true
	}

	return v
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

	// Check each composition's resources for selectors
	for _, comp := range v.compositions {
		for _, res := range comp.Resources {
			// Check if this resource is a child XR (has a selector)
			// Note: Even empty selectors {} should be validated (they won't match anything)
			if res.CompositionSelector != nil {
				kind := res.Base.GetKind()

				// Find compositions that match this selector and kind
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

	for name, comp := range v.compositions {
		// Skip compositions without labels (can't be selected anyway)
		if len(comp.Labels) == 0 {
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
