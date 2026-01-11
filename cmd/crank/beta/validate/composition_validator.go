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
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/crossplane/crossplane-runtime/v2/pkg/fieldpath"

	"github.com/crossplane/crossplane/v2/cmd/crank/common/load"
)

// CompositionValidationError represents a composition validation error.
type CompositionValidationError struct {
	Composition string
	Resource    string
	SourceFile  string
	SourceLine  int
	Message     string
	Severity    string // "error" or "warning"
}

// CompositionValidationResult holds the results of composition validation.
type CompositionValidationResult struct {
	Errors   []CompositionValidationError
	Warnings []CompositionValidationError
}

// CompositionValidator validates composition-level constraints.
type CompositionValidator struct {
	compositions []*unstructured.Unstructured
	xrds         []*unstructured.Unstructured
	xrdKinds     map[string]bool // Map of XRD kind names
}

// NewCompositionValidator creates a new CompositionValidator.
func NewCompositionValidator(compositions, xrds []*unstructured.Unstructured) *CompositionValidator {
	v := &CompositionValidator{
		compositions: compositions,
		xrds:         xrds,
		xrdKinds:     make(map[string]bool),
	}

	// Build map of XRD kinds
	for _, xrd := range xrds {
		kind, _, _ := unstructured.NestedString(xrd.Object, "spec", "names", "kind")
		if kind != "" {
			v.xrdKinds[kind] = true
		}
	}

	return v
}

// Validate runs all composition validations.
func (v *CompositionValidator) Validate(w io.Writer) (*CompositionValidationResult, error) {
	result := &CompositionValidationResult{
		Errors:   make([]CompositionValidationError, 0),
		Warnings: make([]CompositionValidationError, 0),
	}

	for _, comp := range v.compositions {
		if comp.GetAPIVersion() != "apiextensions.crossplane.io/v1" || comp.GetKind() != "Composition" {
			continue
		}

		// 1. Validate CompositeTypeRef
		if errs := v.validateCompositeTypeRef(comp); len(errs) > 0 {
			result.Errors = append(result.Errors, errs...)
		}

		// 2. Validate PatchSet references
		errs, warns := v.validatePatchSets(comp)
		result.Errors = append(result.Errors, errs...)
		result.Warnings = append(result.Warnings, warns...)

		// 3. Detect duplicate toFieldPath writes
		duplicateWarns := v.detectDuplicateToFieldPaths(comp)
		result.Warnings = append(result.Warnings, duplicateWarns...)
	}

	// Print errors
	for _, err := range result.Errors {
		line := ""
		if err.SourceLine > 0 {
			line = fmt.Sprintf(":%d", err.SourceLine)
		}
		if _, e := fmt.Fprintf(w, "[x] %s%s: %s\n", err.SourceFile, line, err.Message); e != nil {
			return nil, e
		}
	}

	// Print warnings
	for _, warn := range result.Warnings {
		line := ""
		if warn.SourceLine > 0 {
			line = fmt.Sprintf(":%d", warn.SourceLine)
		}
		if _, e := fmt.Fprintf(w, "[!] %s%s: %s\n", warn.SourceFile, line, warn.Message); e != nil {
			return nil, e
		}
	}

	return result, nil
}

// validateCompositeTypeRef validates that the composition's compositeTypeRef references an existing XRD.
func (v *CompositionValidator) validateCompositeTypeRef(comp *unstructured.Unstructured) []CompositionValidationError {
	var errors []CompositionValidationError

	kind, _, err := unstructured.NestedString(comp.Object, "spec", "compositeTypeRef", "kind")
	if err != nil || kind == "" {
		return errors // Skip if no kind specified
	}

	if !v.xrdKinds[kind] {
		sourceFile := load.GetSourceFile(comp)
		sourceLine := load.GetSourceLine(comp)

		errors = append(errors, CompositionValidationError{
			Composition: comp.GetName(),
			SourceFile:  sourceFile,
			SourceLine:  sourceLine,
			Message:     fmt.Sprintf("composition '%s' references unknown XRD kind '%s' in compositeTypeRef", comp.GetName(), kind),
			Severity:    "error",
		})
	}

	return errors
}

// validatePatchSets validates PatchSet definitions and references.
// Returns (errors, warnings).
func (v *CompositionValidator) validatePatchSets(comp *unstructured.Unstructured) ([]CompositionValidationError, []CompositionValidationError) {
	var errors, warnings []CompositionValidationError

	paved := fieldpath.Pave(comp.Object)
	sourceFile := load.GetSourceFile(comp)
	sourceLine := load.GetSourceLine(comp)

	// Get pipeline steps
	pipeline, err := paved.GetValue("spec.pipeline")
	if err != nil {
		return errors, warnings // No pipeline
	}

	pipelineSlice, ok := pipeline.([]interface{})
	if !ok {
		return errors, warnings
	}

	for _, step := range pipelineSlice {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		inputKind, _ := input["kind"].(string)
		if inputKind != "Resources" {
			continue
		}

		// Collect defined PatchSets
		definedPatchSets := make(map[string]bool)
		if patchSets, ok := input["patchSets"].([]interface{}); ok {
			for _, ps := range patchSets {
				psMap, ok := ps.(map[string]interface{})
				if !ok {
					continue
				}
				psName, _ := psMap["name"].(string)
				if psName != "" {
					definedPatchSets[psName] = false // false = not used yet
				}
			}
		}

		// Check PatchSet references in resources
		resources, ok := input["resources"].([]interface{})
		if !ok {
			continue
		}

		for _, res := range resources {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			resName, _ := resMap["name"].(string)

			patches, ok := resMap["patches"].([]interface{})
			if !ok {
				continue
			}

			for _, patch := range patches {
				patchMap, ok := patch.(map[string]interface{})
				if !ok {
					continue
				}

				patchType, _ := patchMap["type"].(string)
				if patchType != "PatchSet" {
					continue
				}

				patchSetName, _ := patchMap["patchSetName"].(string)
				if patchSetName == "" {
					continue
				}

				// Check if PatchSet exists
				if _, exists := definedPatchSets[patchSetName]; !exists {
					errors = append(errors, CompositionValidationError{
						Composition: comp.GetName(),
						Resource:    resName,
						SourceFile:  sourceFile,
						SourceLine:  sourceLine,
						Message:     fmt.Sprintf("resource '%s' references non-existent PatchSet '%s'", resName, patchSetName),
						Severity:    "error",
					})
				} else {
					// Mark as used
					definedPatchSets[patchSetName] = true
				}
			}
		}

		// Check for unused PatchSets
		for psName, used := range definedPatchSets {
			if !used {
				warnings = append(warnings, CompositionValidationError{
					Composition: comp.GetName(),
					SourceFile:  sourceFile,
					SourceLine:  sourceLine,
					Message:     fmt.Sprintf("PatchSet '%s' is defined but never used in composition '%s'", psName, comp.GetName()),
					Severity:    "warning",
				})
			}
		}
	}

	return errors, warnings
}

// detectDuplicateToFieldPaths detects when multiple patches write to the same toFieldPath.
func (v *CompositionValidator) detectDuplicateToFieldPaths(comp *unstructured.Unstructured) []CompositionValidationError {
	var warnings []CompositionValidationError

	paved := fieldpath.Pave(comp.Object)
	sourceFile := load.GetSourceFile(comp)
	sourceLine := load.GetSourceLine(comp)

	// Get pipeline steps
	pipeline, err := paved.GetValue("spec.pipeline")
	if err != nil {
		return warnings
	}

	pipelineSlice, ok := pipeline.([]interface{})
	if !ok {
		return warnings
	}

	for _, step := range pipelineSlice {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		inputKind, _ := input["kind"].(string)
		if inputKind != "Resources" {
			continue
		}

		// Get PatchSets to resolve their patches
		patchSets := make(map[string][]map[string]interface{})
		if ps, ok := input["patchSets"].([]interface{}); ok {
			for _, p := range ps {
				psMap, ok := p.(map[string]interface{})
				if !ok {
					continue
				}
				psName, _ := psMap["name"].(string)
				if psName != "" {
					if patches, ok := psMap["patches"].([]interface{}); ok {
						for _, patch := range patches {
							if patchMap, ok := patch.(map[string]interface{}); ok {
								patchSets[psName] = append(patchSets[psName], patchMap)
							}
						}
					}
				}
			}
		}

		resources, ok := input["resources"].([]interface{})
		if !ok {
			continue
		}

		for _, res := range resources {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			resName, _ := resMap["name"].(string)

			// Track toFieldPaths for this resource
			toFieldPaths := make(map[string][]string) // toFieldPath -> list of sources (patch type/index)

			patches, ok := resMap["patches"].([]interface{})
			if !ok {
				continue
			}

			for i, patch := range patches {
				patchMap, ok := patch.(map[string]interface{})
				if !ok {
					continue
				}

				patchType, _ := patchMap["type"].(string)

				// If it's a PatchSet reference, expand it
				if patchType == "PatchSet" {
					patchSetName, _ := patchMap["patchSetName"].(string)
					if psPatches, ok := patchSets[patchSetName]; ok {
						for j, psPatch := range psPatches {
							toPath, _ := psPatch["toFieldPath"].(string)
							if toPath != "" {
								source := fmt.Sprintf("PatchSet '%s' patch[%d]", patchSetName, j)
								toFieldPaths[toPath] = append(toFieldPaths[toPath], source)
							}
						}
					}
					continue
				}

				// Get toFieldPath for regular patches
				toPath, _ := patchMap["toFieldPath"].(string)
				if toPath != "" {
					source := fmt.Sprintf("patch[%d] (%s)", i, patchType)
					toFieldPaths[toPath] = append(toFieldPaths[toPath], source)
				}
			}

			// Check for duplicates
			for toPath, sources := range toFieldPaths {
				if len(sources) > 1 {
					warnings = append(warnings, CompositionValidationError{
						Composition: comp.GetName(),
						Resource:    resName,
						SourceFile:  sourceFile,
						SourceLine:  sourceLine,
						Message:     fmt.Sprintf("resource '%s' has multiple patches writing to '%s': %s", resName, toPath, strings.Join(sources, ", ")),
						Severity:    "warning",
					})
				}
			}
		}
	}

	return warnings
}

// ValidateCompositeTypeRefs validates that all compositions reference existing XRDs.
// This is a convenience function for standalone use.
func ValidateCompositeTypeRefs(compositions, xrds []*unstructured.Unstructured) []CompositionValidationError {
	var errors []CompositionValidationError

	// Build map of XRD kinds
	xrdKinds := make(map[string]bool)
	for _, xrd := range xrds {
		kind, _, _ := unstructured.NestedString(xrd.Object, "spec", "names", "kind")
		if kind != "" {
			xrdKinds[kind] = true
		}
	}

	for _, comp := range compositions {
		if comp.GetAPIVersion() != "apiextensions.crossplane.io/v1" || comp.GetKind() != "Composition" {
			continue
		}

		kind, _, err := unstructured.NestedString(comp.Object, "spec", "compositeTypeRef", "kind")
		if err != nil || kind == "" {
			continue
		}

		if !xrdKinds[kind] {
			sourceFile := load.GetSourceFile(comp)
			sourceLine := load.GetSourceLine(comp)

			errors = append(errors, CompositionValidationError{
				Composition: comp.GetName(),
				SourceFile:  sourceFile,
				SourceLine:  sourceLine,
				Message:     fmt.Sprintf("composition '%s' references unknown XRD kind '%s'", comp.GetName(), kind),
				Severity:    "error",
			})
		}
	}

	return errors
}

// ExtractCompositionsAndXRDs separates compositions from XRDs.
func ExtractCompositionsAndXRDs(objects []*unstructured.Unstructured) (compositions, xrds []*unstructured.Unstructured) {
	for _, obj := range objects {
		gvk := obj.GroupVersionKind()
		if gvk.Group == "apiextensions.crossplane.io" {
			switch gvk.Kind {
			case "Composition":
				compositions = append(compositions, obj)
			case "CompositeResourceDefinition":
				xrds = append(xrds, obj)
			}
		}
	}
	return
}

// GetXRDKindFromAPIVersion extracts the kind from an XRD's compositeTypeRef.
func GetXRDKindFromAPIVersion(apiVersion, kind string) schema.GroupVersionKind {
	parts := strings.Split(apiVersion, "/")
	if len(parts) == 2 {
		return schema.GroupVersionKind{
			Group:   parts[0],
			Version: parts[1],
			Kind:    kind,
		}
	}
	return schema.GroupVersionKind{
		Version: apiVersion,
		Kind:    kind,
	}
}
