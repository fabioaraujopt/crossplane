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

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// PatchTypeMismatchValidator validates that patch source and target types are compatible.
type PatchTypeMismatchValidator struct {
	navigator    *SchemaNavigator
	compositions []*ParsedComposition
}

// TypeMismatchError represents a type mismatch between source and target fields.
type TypeMismatchError struct {
	CompositionName string
	ResourceName    string
	PatchIndex      int
	FromFieldPath   string
	ToFieldPath     string
	SourceType      string
	TargetType      string
	Message         string
	Severity        string // "error" or "warning"
}

func (e TypeMismatchError) Error() string {
	return fmt.Sprintf("composition '%s' resource '%s' patch[%d]: %s",
		e.CompositionName, e.ResourceName, e.PatchIndex, e.Message)
}

// NewPatchTypeMismatchValidator creates a new validator.
func NewPatchTypeMismatchValidator(navigator *SchemaNavigator, compositions []*ParsedComposition) *PatchTypeMismatchValidator {
	return &PatchTypeMismatchValidator{
		navigator:    navigator,
		compositions: compositions,
	}
}

// Validate checks all patches for type mismatches.
func (v *PatchTypeMismatchValidator) Validate() []TypeMismatchError {
	var errors []TypeMismatchError

	for _, comp := range v.compositions {
		// Get XR schema for FromCompositeFieldPath
		xrSchema := v.navigator.GetSchemaForGVK(comp.CompositeTypeRef)

		for _, res := range comp.Resources {
			// Get target resource schema
			var targetSchema *extv1.JSONSchemaProps
			if res.Base != nil {
				targetSchema = v.navigator.GetSchemaForGVK(res.Base.GroupVersionKind())
			}

			for i, patch := range res.Patches {
				patchErrors := v.validatePatchTypes(comp.Name, res.Name, i, patch, xrSchema, targetSchema)
				errors = append(errors, patchErrors...)
			}
		}

		// Also validate patches from AllPatches
		for _, patchInfo := range comp.AllPatches {
			xrSchema := v.navigator.GetSchemaForGVK(patchInfo.SourceGVK)
			targetSchema := v.navigator.GetSchemaForGVK(patchInfo.TargetGVK)
			patchErrors := v.validatePatchTypes(
				patchInfo.CompositionName,
				patchInfo.ResourceName,
				patchInfo.PatchIndex,
				patchInfo.Patch,
				xrSchema,
				targetSchema,
			)
			errors = append(errors, patchErrors...)
		}
	}

	return errors
}

// validatePatchTypes validates type compatibility for a single patch.
func (v *PatchTypeMismatchValidator) validatePatchTypes(
	compName, resName string,
	patchIndex int,
	patch Patch,
	sourceSchema, targetSchema *extv1.JSONSchemaProps,
) []TypeMismatchError {
	var errors []TypeMismatchError

	// Normalize patch type
	patchType := patch.Type
	if patchType == "" {
		patchType = PatchTypeFromCompositeFieldPath
	}

	switch patchType {
	case PatchTypeFromCompositeFieldPath:
		if sourceSchema != nil && targetSchema != nil && patch.FromFieldPath != "" && patch.ToFieldPath != "" {
			err := v.checkTypeCompatibility(
				compName, resName, patchIndex,
				patch.FromFieldPath, patch.ToFieldPath,
				sourceSchema, targetSchema,
				patch.Transforms,
			)
			if err != nil {
				errors = append(errors, *err)
			}
		}

	case PatchTypeToCompositeFieldPath:
		// Source is the managed resource, target is the XR
		if sourceSchema != nil && targetSchema != nil && patch.FromFieldPath != "" && patch.ToFieldPath != "" {
			err := v.checkTypeCompatibility(
				compName, resName, patchIndex,
				patch.FromFieldPath, patch.ToFieldPath,
				targetSchema, sourceSchema, // Swapped!
				patch.Transforms,
			)
			if err != nil {
				errors = append(errors, *err)
			}
		}

	case PatchTypeCombineFromComposite:
		// Combined result goes to target - harder to validate, skip for now
		// Would need to infer result type from combine strategy

	case PatchTypeCombineToComposite:
		// Combined result goes to XR status - harder to validate, skip for now
	}

	return errors
}

// checkTypeCompatibility compares source and target field types.
func (v *PatchTypeMismatchValidator) checkTypeCompatibility(
	compName, resName string,
	patchIndex int,
	fromPath, toPath string,
	sourceSchema, targetSchema *extv1.JSONSchemaProps,
	transforms []Transform,
) *TypeMismatchError {
	sourceType := v.getFieldType(sourceSchema, fromPath)
	targetType := v.getFieldType(targetSchema, toPath)

	// If we couldn't determine types, skip
	if sourceType == "" || targetType == "" {
		return nil
	}

	// Check if transforms change the type
	finalSourceType := v.applyTransformTypes(sourceType, transforms)

	// Check compatibility
	if !v.typesCompatible(finalSourceType, targetType) {
		return &TypeMismatchError{
			CompositionName: compName,
			ResourceName:    resName,
			PatchIndex:      patchIndex,
			FromFieldPath:   fromPath,
			ToFieldPath:     toPath,
			SourceType:      finalSourceType,
			TargetType:      targetType,
			Message: fmt.Sprintf("type mismatch: '%s' (%s) → '%s' (%s)",
				fromPath, finalSourceType, toPath, targetType),
			Severity: "error",
		}
	}

	return nil
}

// getFieldType traverses schema to find the type at a path.
func (v *PatchTypeMismatchValidator) getFieldType(schema *extv1.JSONSchemaProps, path string) string {
	if schema == nil || path == "" {
		return ""
	}

	parts := strings.Split(path, ".")
	current := schema

	for _, part := range parts {
		if current == nil {
			return ""
		}

		// Handle array/map indexing like "items[0]" or "matchLabels["key"]"
		cleanPart := part
		hasBracket := false
		if idx := strings.Index(part, "["); idx != -1 {
			cleanPart = part[:idx]
			hasBracket = true
		}

		// Check properties
		if current.Properties != nil {
			if prop, ok := current.Properties[cleanPart]; ok {
				current = &prop

				// If we accessed with bracket notation, determine if it's array or map
				if hasBracket {
					// Check if it's a map (has additionalProperties) - common for labels/annotations
					if current.AdditionalProperties != nil && current.AdditionalProperties.Schema != nil {
						current = current.AdditionalProperties.Schema
					} else if current.Items != nil && current.Items.Schema != nil {
						// It's an array - dive into items
						current = current.Items.Schema
					}
					// If neither, current stays as the property type (might be x-kubernetes-preserve-unknown-fields)
				}
				continue
			}
		}

		// Check additionalProperties (for maps like labels)
		if current.AdditionalProperties != nil && current.AdditionalProperties.Schema != nil {
			current = current.AdditionalProperties.Schema
			continue
		}

		// Check items (for arrays)
		if current.Items != nil && current.Items.Schema != nil {
			current = current.Items.Schema
			continue
		}

		return ""
	}

	if current == nil {
		return ""
	}

	return current.Type
}

// applyTransformTypes determines the output type after transforms.
func (v *PatchTypeMismatchValidator) applyTransformTypes(inputType string, transforms []Transform) string {
	currentType := inputType

	for _, transform := range transforms {
		switch transform.Type {
		case "convert":
			// Convert transform explicitly changes type
			if transform.Convert != nil && transform.Convert.ToType != "" {
				currentType = transform.Convert.ToType
			}
		case "string":
			// String transforms output string
			currentType = "string"
		case "math":
			// Math transforms work on numbers, output number
			if currentType == "integer" || currentType == "number" {
				// Keep the same type
			}
		case "map":
			// Map transform - output depends on map values
			// Usually string → string, but can't know for sure
			// Keep current type as approximation
		case "match":
			// Match transform - similar to map
		}
	}

	return currentType
}

// typesCompatible checks if two types are compatible.
func (v *PatchTypeMismatchValidator) typesCompatible(source, target string) bool {
	// Exact match
	if source == target {
		return true
	}

	// Empty means unknown - allow it
	if source == "" || target == "" {
		return true
	}

	// Common compatible pairs
	compatible := map[string][]string{
		"integer": {"number", "integer", "string"}, // int can go to number or be stringified
		"number":  {"number", "integer", "string"}, // number can go to int (truncated) or string
		"boolean": {"boolean", "string"},           // bool can be stringified
		"string":  {"string"},                      // string is only compatible with string
		"array":   {"array"},
		"object":  {"object"},
	}

	if allowed, ok := compatible[source]; ok {
		for _, t := range allowed {
			if t == target {
				return true
			}
		}
	}

	return false
}

// ValidateStatusTypes specifically validates status field type consistency.
func (v *PatchTypeMismatchValidator) ValidateStatusTypes() []TypeMismatchError {
	var errors []TypeMismatchError

	// For status propagation: parent reads status.X from child
	// Check if parent's status.X type matches child's status.X type

	// Group compositions by XR kind
	compsByKind := make(map[string][]*ParsedComposition)
	for _, comp := range v.compositions {
		kind := comp.CompositeTypeRef.Kind
		compsByKind[kind] = append(compsByKind[kind], comp)
	}

	// For each composition, find ToCompositeFieldPath patches that read from child status
	for _, comp := range v.compositions {
		parentSchema := v.navigator.GetSchemaForGVK(comp.CompositeTypeRef)
		if parentSchema == nil {
			continue
		}

		for _, patchInfo := range comp.AllPatches {
			if patchInfo.Patch.Type != PatchTypeToCompositeFieldPath {
				continue
			}

			// This patch reads from child (fromFieldPath) and writes to parent (toFieldPath)
			if !strings.HasPrefix(patchInfo.Patch.FromFieldPath, "status.") {
				continue
			}

			// Get child schema
			childSchema := v.navigator.GetSchemaForGVK(patchInfo.SourceGVK)
			if childSchema == nil {
				continue
			}

			// Compare types
			childType := v.getFieldType(childSchema, patchInfo.Patch.FromFieldPath)
			parentType := v.getFieldType(parentSchema, patchInfo.Patch.ToFieldPath)

			if childType != "" && parentType != "" && childType != parentType {
				errors = append(errors, TypeMismatchError{
					CompositionName: patchInfo.CompositionName,
					ResourceName:    patchInfo.ResourceName,
					PatchIndex:      patchInfo.PatchIndex,
					FromFieldPath:   patchInfo.Patch.FromFieldPath,
					ToFieldPath:     patchInfo.Patch.ToFieldPath,
					SourceType:      childType,
					TargetType:      parentType,
					Message: fmt.Sprintf("status type mismatch: child '%s' (%s) → parent '%s' (%s)",
						patchInfo.Patch.FromFieldPath, childType,
						patchInfo.Patch.ToFieldPath, parentType),
					Severity: "error",
				})
			}
		}
	}

	return errors
}
