// Package validate provides validation for Crossplane compositions.
package validate

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// formatPlaceholderRegex matches Go format verbs with optional positional index, flags, width, and precision.
// Pattern breakdown:
//   %           - literal percent sign
//   (?:\[(\d+)\])? - optional positional index like [1], [2], capturing the number
//   [-+# 0]*    - optional flags (-, +, #, space, 0)
//   (?:\*|\d+)? - optional width (either * or digits)
//   (?:\.(?:\*|\d+))? - optional precision (. followed by * or digits)
//   [vtbcdoOqxXUeEfFgGspT] - the format verb (excludes % which is escape, not a placeholder)
//
// Examples matched: %s, %d, %v, %[1]s, %[2]d, %-10s, %5.2f, %#x, %+v
var formatPlaceholderRegex = regexp.MustCompile(`%(?:\[(\d+)\])?[-+# 0]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[vtbcdoOqxXUeEfFgGspT]`)

// countFormatPlaceholders counts the number of arguments needed by a Go format string.
// It handles:
//   - Simple placeholders: %s, %d, %v, etc.
//   - Positional placeholders: %[1]s, %[2]d, etc. (uses max index as count)
//   - Mixed: positional + non-positional (accounts for continuation after positional)
//   - Width/precision with flags: %-10s, %5.2f, %#x
//
// Note: %% (escaped percent) is not counted as it doesn't consume an argument.
func countFormatPlaceholders(format string) int {
	// First, remove %% escapes (literal percent signs) to avoid false matches
	// For example: "100%% complete" should have 0 placeholders, not match "% c"
	cleanFormat := strings.ReplaceAll(format, "%%", "")

	matches := formatPlaceholderRegex.FindAllStringSubmatch(cleanFormat, -1)
	if len(matches) == 0 {
		return 0
	}

	maxPositionalIndex := 0
	lastPositionalPos := -1

	for i, match := range matches {
		if len(match) > 1 && match[1] != "" {
			// Positional argument: %[N]verb - capture group 1 has the number
			idx := 0
			for _, c := range match[1] {
				idx = idx*10 + int(c-'0')
			}
			if idx > maxPositionalIndex {
				maxPositionalIndex = idx
			}
			lastPositionalPos = i
		}
	}

	if maxPositionalIndex == 0 {
		// No positional arguments - count all verbs
		return len(matches)
	}

	// With positional arguments:
	// The max index tells us the minimum required arguments
	// Non-positional verbs after the last positional continue from that index
	nonPositionalAfterLast := 0
	for i := lastPositionalPos + 1; i < len(matches); i++ {
		if len(matches[i]) <= 1 || matches[i][1] == "" {
			nonPositionalAfterLast++
		}
	}

	return maxPositionalIndex + nonPositionalAfterLast
}

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
		compErrors, compWarnings := v.validateComposition(comp)
		result.Errors = append(result.Errors, compErrors...)
		result.Warnings = append(result.Warnings, compWarnings...)
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
func (v *PatchTypeValidator) validateComposition(comp *ParsedComposition) ([]PatchTypeValidationError, []PatchTypeValidationError) {
	var errors []PatchTypeValidationError
	var warnings []PatchTypeValidationError

	for _, patchInfo := range comp.AllPatches {
		patchErrors, patchWarnings := v.validatePatch(comp.Name, patchInfo)
		errors = append(errors, patchErrors...)
		warnings = append(warnings, patchWarnings...)
	}

	return errors, warnings
}

// validatePatch validates a single patch has required fields for its type.
// Returns (errors, warnings) where errors are critical issues and warnings are recommendations.
func (v *PatchTypeValidator) validatePatch(compName string, patchInfo PatchInfo) ([]PatchTypeValidationError, []PatchTypeValidationError) {
	var allResults []PatchTypeValidationError
	patch := patchInfo.Patch

	// Normalize empty type to default
	patchType := patch.Type
	if patchType == "" {
		patchType = PatchTypeFromCompositeFieldPath
	}

	switch patchType {
	case PatchTypeFromCompositeFieldPath:
		allResults = append(allResults, v.validateFromCompositeFieldPath(compName, patchInfo)...)

	case PatchTypeToCompositeFieldPath:
		allResults = append(allResults, v.validateToCompositeFieldPath(compName, patchInfo)...)

	case PatchTypeCombineFromComposite:
		allResults = append(allResults, v.validateCombineFromComposite(compName, patchInfo)...)

	case PatchTypeCombineToComposite:
		allResults = append(allResults, v.validateCombineToComposite(compName, patchInfo)...)

	case PatchTypePatchSet:
		allResults = append(allResults, v.validatePatchSetRef(compName, patchInfo)...)

	case PatchTypeFromEnvironmentFieldPath:
		allResults = append(allResults, v.validateFromEnvironmentFieldPath(compName, patchInfo)...)

	case PatchTypeToEnvironmentFieldPath:
		allResults = append(allResults, v.validateToEnvironmentFieldPath(compName, patchInfo)...)
	}

	// Separate errors and warnings based on Severity
	var errors, warnings []PatchTypeValidationError
	for _, result := range allResults {
		if result.Severity == "warning" {
			warnings = append(warnings, result)
		} else {
			errors = append(errors, result)
		}
	}

	return errors, warnings
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

	// Validate status dependency has Required policy
	errors = append(errors, v.validateStatusDependencyPolicy(compName, patchInfo, patch.FromFieldPath)...)

	return errors
}

// validateStatusDependencyPolicy checks if a patch reading from status.* has Required policy.
// Status fields are populated by other resources, so the patch should use Required policy
// to ensure the resource waits for the status to be available.
// Without Required, resources may be created with empty values, causing runtime failures.
func (v *PatchTypeValidator) validateStatusDependencyPolicy(compName string, patchInfo PatchInfo, fromFieldPath string) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	// Check if reading from status.* fields (dependency on another resource's output)
	if strings.HasPrefix(fromFieldPath, "status.") {
		hasRequiredPolicy := patch.Policy != nil && patch.Policy.FromFieldPath == "Required"

		if !hasRequiredPolicy {
			errors = append(errors, PatchTypeValidationError{
				CompositionName: compName,
				ResourceName:    patchInfo.ResourceName,
				PatchIndex:      patchInfo.PatchIndex,
				PatchType:       string(patch.Type),
				SourceFile:      patchInfo.SourceFile,
				SourceLine:      patchInfo.SourceLine,
				Message: fmt.Sprintf(
					"composition '%s' resource '%s' patch[%d]: reading from '%s' (status dependency) requires 'policy.fromFieldPath: Required' - without it, the resource may be created before the status field is populated, causing runtime failures",
					compName, patchInfo.ResourceName, patchInfo.PatchIndex, fromFieldPath),
				Severity: "error",
			})
		}
	}

	return errors
}

// validateCombineStatusDependencies checks if a CombineFromComposite patch reading from status.* has Required policy.
// Without Required, resources may be created with empty values in format strings, causing runtime failures.
func (v *PatchTypeValidator) validateCombineStatusDependencies(compName string, patchInfo PatchInfo) []PatchTypeValidationError {
	var errors []PatchTypeValidationError
	patch := patchInfo.Patch

	if patch.Combine == nil {
		return errors
	}

	// Check if any variable reads from status.* fields
	var statusVariables []string
	for _, variable := range patch.Combine.Variables {
		if strings.HasPrefix(variable.FromFieldPath, "status.") {
			statusVariables = append(statusVariables, variable.FromFieldPath)
		}
	}

	// If there are status dependencies without Required policy, error
	if len(statusVariables) > 0 {
		hasRequiredPolicy := patch.Policy != nil && patch.Policy.FromFieldPath == "Required"

		if !hasRequiredPolicy {
			errors = append(errors, PatchTypeValidationError{
				CompositionName: compName,
				ResourceName:    patchInfo.ResourceName,
				PatchIndex:      patchInfo.PatchIndex,
				PatchType:       string(patch.Type),
				SourceFile:      patchInfo.SourceFile,
				SourceLine:      patchInfo.SourceLine,
				Message: fmt.Sprintf(
					"composition '%s' resource '%s' patch[%d]: combine patch reads from status fields %v (status dependency) requires 'policy.fromFieldPath: Required' - without it, the resource may be created before status fields are populated, causing runtime failures",
					compName, patchInfo.ResourceName, patchInfo.PatchIndex, statusVariables),
				Severity: "error",
			})
		}
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

	// Validate status dependencies in combine variables have Required policy
	errors = append(errors, v.validateCombineStatusDependencies(compName, patchInfo)...)

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

	// Validate format string placeholder count matches variable count
	if patch.Combine.String != nil && patch.Combine.String.Format != "" {
		placeholderCount := countFormatPlaceholders(patch.Combine.String.Format)
		variableCount := len(patch.Combine.Variables)

		if placeholderCount != variableCount {
			errors = append(errors, PatchTypeValidationError{
				CompositionName: compName,
				ResourceName:    patchInfo.ResourceName,
				PatchIndex:      patchInfo.PatchIndex,
				PatchType:       string(PatchTypeCombineFromComposite),
				SourceFile:      patchInfo.SourceFile,
				SourceLine:      patchInfo.SourceLine,
				Message: fmt.Sprintf(
					"composition '%s' resource '%s' patch[%d]: format string has %d placeholder(s) but %d variable(s) defined - mismatch will cause runtime error",
					compName, patchInfo.ResourceName, patchInfo.PatchIndex, placeholderCount, variableCount),
				Severity: "error",
			})
		}

		// Validate JSON template if toFieldPath suggests it should be JSON
		if isJSONField(patch.ToFieldPath) {
			if err := validateJSONTemplate(patch.Combine.String.Format, variableCount); err != nil {
				errors = append(errors, PatchTypeValidationError{
					CompositionName: compName,
					ResourceName:    patchInfo.ResourceName,
					PatchIndex:      patchInfo.PatchIndex,
					PatchType:       string(PatchTypeCombineFromComposite),
					SourceFile:      patchInfo.SourceFile,
					SourceLine:      patchInfo.SourceLine,
					Message: fmt.Sprintf(
						"composition '%s' resource '%s' patch[%d]: format string template appears to be invalid JSON: %v",
						compName, patchInfo.ResourceName, patchInfo.PatchIndex, err),
					Severity: "warning",
				})
			}
		}
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

// isJSONField checks if a field path likely contains JSON data.
func isJSONField(fieldPath string) bool {
	fieldLower := strings.ToLower(fieldPath)
	return strings.Contains(fieldLower, "policy") ||
		strings.Contains(fieldLower, "json") ||
		strings.Contains(fieldLower, "assumerolepolicy") ||
		strings.Contains(fieldLower, "document")
}

// validateJSONTemplate validates that a format string template produces valid JSON.
func validateJSONTemplate(template string, variableCount int) error {
	// Replace all %s placeholders with dummy values
	testStr := template
	for i := 0; i < variableCount; i++ {
		testStr = strings.Replace(testStr, "%s", "test-value", 1)
	}

	// Try to parse as JSON
	var js interface{}
	if err := json.Unmarshal([]byte(testStr), &js); err != nil {
		return err
	}

	return nil
}
