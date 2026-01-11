// Package validate provides validation for Crossplane compositions.
package validate

import (
	"fmt"
	"io"
	"strings"
)

// PatchTypeValidationError represents a patch type validation error.
type PatchTypeValidationError struct {
	CompositionName string
	ResourceName    string
	PatchIndex      int
	PatchType       string
	SourceFile      string
	SourceLine      int
	Message         string
	Severity        string // "error" or "warning"
}

// PatchTypeValidationResult holds the results of patch type validation.
type PatchTypeValidationResult struct {
	Errors   []PatchTypeValidationError
	Warnings []PatchTypeValidationError
}

// PatchTypeValidator validates that patches have required fields for their type.
type PatchTypeValidator struct {
	compositions []*ParsedComposition
}

// NewPatchTypeValidator creates a new validator.
func NewPatchTypeValidator(compositions []*ParsedComposition) *PatchTypeValidator {
	return &PatchTypeValidator{
		compositions: compositions,
	}
}

// Validate runs all patch type validations.
func (v *PatchTypeValidator) Validate(w io.Writer) (*PatchTypeValidationResult, error) {
	result := &PatchTypeValidationResult{}

	for _, comp := range v.compositions {
		compErrors := v.validateComposition(comp)
		result.Errors = append(result.Errors, compErrors...)
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

// validateComposition validates all patches in a composition.
func (v *PatchTypeValidator) validateComposition(comp *ParsedComposition) []PatchTypeValidationError {
	var errors []PatchTypeValidationError

	for _, patchInfo := range comp.AllPatches {
		patchErrors := v.validatePatch(comp.Name, patchInfo)
		errors = append(errors, patchErrors...)
	}

	return errors
}

// validatePatch validates a single patch has required fields for its type.
func (v *PatchTypeValidator) validatePatch(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Normalize empty type to default
	patchType := patch.Type
	if patchType == "" {
		patchType = PatchTypeFromCompositeFieldPath
	}

	switch patchType {
	case PatchTypeFromCompositeFieldPath:
		errors = append(errors, v.validateFromCompositeFieldPath(compName, patchInfo)...)

	case PatchTypeToCompositeFieldPath:
		errors = append(errors, v.validateToCompositeFieldPath(compName, patchInfo)...)

	case PatchTypeCombineFromComposite:
		errors = append(errors, v.validateCombineFromComposite(compName, patchInfo)...)

	case PatchTypeCombineToComposite:
		errors = append(errors, v.validateCombineToComposite(compName, patchInfo)...)

	case PatchTypePatchSet:
		errors = append(errors, v.validatePatchSetRef(compName, patchInfo)...)

	case PatchTypeFromEnvironmentFieldPath:
		errors = append(errors, v.validateFromEnvironmentFieldPath(compName, patchInfo)...)

	case PatchTypeToEnvironmentFieldPath:
		errors = append(errors, v.validateToEnvironmentFieldPath(compName, patchInfo)...)
	}

	return errors
}

// validateFromCompositeFieldPath validates FromCompositeFieldPath patches.
func (v *PatchTypeValidator) validateFromCompositeFieldPath(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Required: fromFieldPath
	if patch.FromFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeFromCompositeFieldPath),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'FromCompositeFieldPath' requires 'fromFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	return errors
}

// validateToCompositeFieldPath validates ToCompositeFieldPath patches.
func (v *PatchTypeValidator) validateToCompositeFieldPath(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Required: fromFieldPath (source from composed resource)
	if patch.FromFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeToCompositeFieldPath),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'ToCompositeFieldPath' requires 'fromFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	// Required: toFieldPath (target in composite)
	if patch.ToFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeToCompositeFieldPath),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'ToCompositeFieldPath' requires 'toFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	return errors
}

// validateCombineFromComposite validates CombineFromComposite patches.
func (v *PatchTypeValidator) validateCombineFromComposite(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Required: combine
	if patch.Combine == nil {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineFromComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineFromComposite' requires 'combine' field",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
		return errors // Can't validate further without combine
	}

	// Required: combine.variables (non-empty)
	if len(patch.Combine.Variables) == 0 {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineFromComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineFromComposite' requires 'combine.variables' with at least one variable",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	// Required: combine.strategy
	if patch.Combine.Strategy == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineFromComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineFromComposite' requires 'combine.strategy' (e.g., 'string', 'fmt')",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	// Validate each variable has fromFieldPath
	for i, variable := range patch.Combine.Variables {
		if variable.FromFieldPath == "" {
			errors = append(errors, PatchTypeValidationError{
				CompositionName: compName,
				ResourceName:    patchInfo.ResourceName,
				PatchIndex:      patchInfo.PatchIndex,
				PatchType:       string(PatchTypeCombineFromComposite),
				SourceFile:      patchInfo.SourceFile,
				SourceLine:      patchInfo.SourceLine,
				Message: fmt.Sprintf(
					"composition '%s' resource '%s' patch[%d]: 'combine.variables[%d]' requires 'fromFieldPath'",
					compName, patchInfo.ResourceName, patchInfo.PatchIndex, i),
				Severity: "error",
			})
		}
	}

	// Required: toFieldPath
	if patch.ToFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineFromComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineFromComposite' requires 'toFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	// Validate strategy value
	validStrategies := []string{"string", "fmt"}
	if patch.Combine.Strategy != "" && !contains(validStrategies, strings.ToLower(patch.Combine.Strategy)) {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineFromComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: invalid 'combine.strategy' value '%s' (valid: string)",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex, patch.Combine.Strategy),
			Severity: "error",
		})
	}

	return errors
}

// validateCombineToComposite validates CombineToComposite patches.
func (v *PatchTypeValidator) validateCombineToComposite(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Required: combine
	if patch.Combine == nil {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineToComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineToComposite' requires 'combine' field",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
		return errors
	}

	// Required: combine.variables (non-empty)
	if len(patch.Combine.Variables) == 0 {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineToComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineToComposite' requires 'combine.variables' with at least one variable",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	// Required: combine.strategy
	if patch.Combine.Strategy == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineToComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineToComposite' requires 'combine.strategy' (e.g., 'string', 'fmt')",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	// Validate each variable has fromFieldPath
	for i, variable := range patch.Combine.Variables {
		if variable.FromFieldPath == "" {
			errors = append(errors, PatchTypeValidationError{
				CompositionName: compName,
				ResourceName:    patchInfo.ResourceName,
				PatchIndex:      patchInfo.PatchIndex,
				PatchType:       string(PatchTypeCombineToComposite),
				SourceFile:      patchInfo.SourceFile,
				SourceLine:      patchInfo.SourceLine,
				Message: fmt.Sprintf(
					"composition '%s' resource '%s' patch[%d]: 'combine.variables[%d]' requires 'fromFieldPath'",
					compName, patchInfo.ResourceName, patchInfo.PatchIndex, i),
				Severity: "error",
			})
		}
	}

	// Required: toFieldPath
	if patch.ToFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeCombineToComposite),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'CombineToComposite' requires 'toFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	return errors
}

// validatePatchSetRef validates PatchSet reference patches.
func (v *PatchTypeValidator) validatePatchSetRef(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Required: patchSetName
	if patch.PatchSetName == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypePatchSet),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'PatchSet' requires 'patchSetName'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	return errors
}

// validateFromEnvironmentFieldPath validates FromEnvironmentFieldPath patches.
func (v *PatchTypeValidator) validateFromEnvironmentFieldPath(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Required: fromFieldPath
	if patch.FromFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeFromEnvironmentFieldPath),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'FromEnvironmentFieldPath' requires 'fromFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	return errors
}

// validateToEnvironmentFieldPath validates ToEnvironmentFieldPath patches.
func (v *PatchTypeValidator) validateToEnvironmentFieldPath(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Required: fromFieldPath
	if patch.FromFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeToEnvironmentFieldPath),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'ToEnvironmentFieldPath' requires 'fromFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	// Required: toFieldPath
	if patch.ToFieldPath == "" {
		errors = append(errors, PatchTypeValidationError{
			CompositionName: compName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			PatchType:       string(PatchTypeToEnvironmentFieldPath),
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
			Message: fmt.Sprintf(
				"composition '%s' resource '%s' patch[%d]: 'ToEnvironmentFieldPath' requires 'toFieldPath'",
				compName, patchInfo.ResourceName, patchInfo.PatchIndex),
			Severity: "error",
		})
	}

	return errors
}

// contains checks if a slice contains a string.
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
