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

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
)

// formatLocation formats a file path and line number into a location string.
func formatLocation(file string, line int) string {
	if file == "" {
		return ""
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return file
}

// PatchValidationConfig holds configuration for patch validation.
type PatchValidationConfig struct {
	// ValidatePatchPaths enables validation of fromFieldPath and toFieldPath against schemas
	ValidatePatchPaths bool
	// DetectUnusedParams enables detection of unused XRD parameters
	DetectUnusedParams bool
	// StrictMode treats warnings as errors
	StrictMode bool
	// SkipMissingSchemas silently skips validation for resources without schemas
	SkipMissingSchemas bool
	// ShowTree shows composition hierarchy tree
	ShowTree bool
	// OnlyInvalid only shows invalid/error results
	OnlyInvalid bool
}

// PatchValidationResult contains the results of patch validation.
type PatchValidationResult struct {
	TotalPatches       int
	ValidPatches       int
	InvalidPatches     int
	SkippedPatches     int // Patches skipped due to missing schemas
	TotalParameters    int
	UsedParameters     int
	UnusedParameters   int
	InvalidPaths       []InvalidPathInfo
	UnusedParams       []ParameterUsage
	Warnings           []string
	Errors             []string
	CompositionsLoaded int
}

// PatchValidator performs comprehensive patch validation.
type PatchValidator struct {
	config    PatchValidationConfig
	navigator *SchemaNavigator
	parser    *CompositionParser
	analyzer  *ParamAnalyzer
	crds      []*extv1.CustomResourceDefinition
}

// NewPatchValidator creates a new PatchValidator.
func NewPatchValidator(crds []*extv1.CustomResourceDefinition, config PatchValidationConfig) *PatchValidator {
	parser := NewCompositionParser()

	return &PatchValidator{
		config:    config,
		navigator: NewSchemaNavigator(crds),
		parser:    parser,
		crds:      crds,
	}
}

// LoadCompositions parses compositions from unstructured objects.
func (v *PatchValidator) LoadCompositions(objects []*unstructured.Unstructured) error {
	return v.parser.Parse(objects)
}

// Validate performs all configured validations.
func (v *PatchValidator) Validate(w io.Writer) (*PatchValidationResult, error) {
	result := &PatchValidationResult{
		InvalidPaths:       make([]InvalidPathInfo, 0),
		UnusedParams:       make([]ParameterUsage, 0),
		Warnings:           make([]string, 0),
		Errors:             make([]string, 0),
		CompositionsLoaded: len(v.parser.GetCompositions()),
	}

	if result.CompositionsLoaded == 0 {
		result.Warnings = append(result.Warnings, "No compositions found to validate")
		return result, nil
	}

	// Print header (skip if OnlyInvalid and no issues yet)
	if !v.config.OnlyInvalid {
		if _, err := fmt.Fprintf(w, "\n=== Composition Patch Validation ===\n"); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}

		if _, err := fmt.Fprintf(w, "Loaded %d compositions\n", result.CompositionsLoaded); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}
	}

	// Create analyzer
	v.analyzer = NewParamAnalyzer(v.crds, v.parser)

	// Validate patch paths if enabled
	if v.config.ValidatePatchPaths {
		if err := v.validatePatchPaths(w, result); err != nil {
			return nil, err
		}
	}

	// Detect unused parameters if enabled
	if v.config.DetectUnusedParams {
		if err := v.detectUnusedParams(w, result); err != nil {
			return nil, err
		}
	}

	// Print summary
	if err := v.printSummary(w, result); err != nil {
		return nil, err
	}

	return result, nil
}

func (v *PatchValidator) validatePatchPaths(w io.Writer, result *PatchValidationResult) error {
	if !v.config.OnlyInvalid {
		if _, err := fmt.Fprintf(w, "\n--- Validating Patch Paths ---\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	for _, comp := range v.parser.GetCompositions() {
		// Check if we have schema for the composite type
		if !v.navigator.HasSchema(comp.CompositeTypeRef) {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"No schema found for composite type %s in composition %s",
				comp.CompositeTypeRef.String(), comp.Name))
			if !v.config.SkipMissingSchemas {
				if _, err := fmt.Fprintf(w, "[!] Skipping composition %s: no schema for %s\n",
					comp.Name, comp.CompositeTypeRef.String()); err != nil {
					return errors.Wrap(err, "cannot write output")
				}
			}
			continue
		}

		for _, patchInfo := range comp.AllPatches {
			result.TotalPatches++

			hasError := false

			// Validate fromFieldPath
			if patchInfo.Patch.FromFieldPath != "" {
				if v.navigator.HasSchema(patchInfo.SourceGVK) {
					validation := v.navigator.ValidatePath(patchInfo.SourceGVK, patchInfo.Patch.FromFieldPath)
					if !validation.Valid {
						hasError = true
						invalidPath := InvalidPathInfo{
							CompositionName: patchInfo.CompositionName,
							ResourceName:    patchInfo.ResourceName,
							PatchIndex:      patchInfo.PatchIndex,
							Path:            patchInfo.Patch.FromFieldPath,
							PathType:        "fromFieldPath",
							Reason:          fmt.Sprintf("%s (at '%s')", validation.Reason, validation.InvalidSegment),
							SourceGVK:       patchInfo.SourceGVK,
							TargetGVK:       patchInfo.TargetGVK,
							SourceFile:      patchInfo.SourceFile,
							SourceLine:      patchInfo.SourceLine,
						}
						result.InvalidPaths = append(result.InvalidPaths, invalidPath)

						// Print with file location and line number if available
						location := formatLocation(patchInfo.SourceFile, patchInfo.SourceLine)
						if location != "" {
							if _, err := fmt.Fprintf(w, "[x] %s %s/%s patch[%d]: fromFieldPath '%s' is invalid - %s\n",
								location, patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
								patchInfo.Patch.FromFieldPath, invalidPath.Reason); err != nil {
								return errors.Wrap(err, "cannot write output")
							}
						} else {
							if _, err := fmt.Fprintf(w, "[x] %s/%s patch[%d]: fromFieldPath '%s' is invalid - %s\n",
								patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
								patchInfo.Patch.FromFieldPath, invalidPath.Reason); err != nil {
								return errors.Wrap(err, "cannot write output")
							}
						}
					}
				} else {
					result.SkippedPatches++
				}
			}

			// Validate toFieldPath
			if patchInfo.Patch.ToFieldPath != "" {
				validated := false
				if v.navigator.HasSchema(patchInfo.TargetGVK) {
					validation := v.navigator.ValidatePath(patchInfo.TargetGVK, patchInfo.Patch.ToFieldPath)
					if !validation.Valid {
						// Check if the validation stopped at a preserve-unknown-fields boundary
						// and we can validate the nested path against a nested resource
						if validation.StoppedAtPreserveUnknown && v.validateNestedPath(comp, patchInfo, &validation, w, result) {
							// Successfully validated nested path
							validated = true
						} else if !validation.StoppedAtPreserveUnknown {
							hasError = true
							invalidPath := InvalidPathInfo{
								CompositionName: patchInfo.CompositionName,
								ResourceName:    patchInfo.ResourceName,
								PatchIndex:      patchInfo.PatchIndex,
								Path:            patchInfo.Patch.ToFieldPath,
								PathType:        "toFieldPath",
								Reason:          fmt.Sprintf("%s (at '%s')", validation.Reason, validation.InvalidSegment),
								SourceGVK:       patchInfo.SourceGVK,
								TargetGVK:       patchInfo.TargetGVK,
								SourceFile:      patchInfo.SourceFile,
								SourceLine:      patchInfo.SourceLine,
							}
							result.InvalidPaths = append(result.InvalidPaths, invalidPath)

							location := formatLocation(patchInfo.SourceFile, patchInfo.SourceLine)
							if location != "" {
								if _, err := fmt.Fprintf(w, "[x] %s %s/%s patch[%d]: toFieldPath '%s' is invalid - %s\n",
									location, patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
									patchInfo.Patch.ToFieldPath, invalidPath.Reason); err != nil {
									return errors.Wrap(err, "cannot write output")
								}
							} else {
								if _, err := fmt.Fprintf(w, "[x] %s/%s patch[%d]: toFieldPath '%s' is invalid - %s\n",
									patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
									patchInfo.Patch.ToFieldPath, invalidPath.Reason); err != nil {
									return errors.Wrap(err, "cannot write output")
								}
							}
						}
					} else {
						validated = true
					}
				}
				if !validated {
					result.SkippedPatches++
				}
			}

			// Validate object-to-object patches: check that all source fields exist in target
			// This catches cases where an entire object is patched but the target schema is missing fields
			if patchInfo.Patch.FromFieldPath != "" && patchInfo.Patch.ToFieldPath != "" {
				if v.navigator.HasSchema(patchInfo.SourceGVK) && v.navigator.HasSchema(patchInfo.TargetGVK) {
					// Check source and target schemas at the path
					sourceValidation := v.navigator.ValidatePath(patchInfo.SourceGVK, patchInfo.Patch.FromFieldPath)
					targetValidation := v.navigator.ValidatePath(patchInfo.TargetGVK, patchInfo.Patch.ToFieldPath)

					// If both paths are valid and both are objects, compare their schemas
					if sourceValidation.Valid && targetValidation.Valid &&
						sourceValidation.SchemaType == "object" && targetValidation.SchemaType == "object" {
						mismatches := v.navigator.CompareObjectSchemas(
							patchInfo.SourceGVK,
							patchInfo.TargetGVK,
							patchInfo.Patch.FromFieldPath,
						)

						for _, mismatch := range mismatches {
							hasError = true
							fullPath := patchInfo.Patch.ToFieldPath + "." + mismatch.Path
							invalidPath := InvalidPathInfo{
								CompositionName: patchInfo.CompositionName,
								ResourceName:    patchInfo.ResourceName,
								PatchIndex:      patchInfo.PatchIndex,
								Path:            fullPath,
								PathType:        "toFieldPath (object child)",
								Reason:          fmt.Sprintf("field '%s' exists in source (%s) but not in target schema", mismatch.Path, patchInfo.SourceGVK.Kind),
								SourceGVK:       patchInfo.SourceGVK,
								TargetGVK:       patchInfo.TargetGVK,
								SourceFile:      patchInfo.SourceFile,
								SourceLine:      patchInfo.SourceLine,
							}
							result.InvalidPaths = append(result.InvalidPaths, invalidPath)

							location := formatLocation(patchInfo.SourceFile, patchInfo.SourceLine)
							if location != "" {
								if _, err := fmt.Fprintf(w, "[x] %s %s/%s patch[%d]: object patch missing field in target - '%s' exists in %s but not in %s\n",
									location, patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
									mismatch.Path, patchInfo.SourceGVK.Kind, patchInfo.TargetGVK.Kind); err != nil {
									return errors.Wrap(err, "cannot write output")
								}
							} else {
								if _, err := fmt.Fprintf(w, "[x] %s/%s patch[%d]: object patch missing field in target - '%s' exists in %s but not in %s\n",
									patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
									mismatch.Path, patchInfo.SourceGVK.Kind, patchInfo.TargetGVK.Kind); err != nil {
									return errors.Wrap(err, "cannot write output")
								}
							}
						}
					}
				}
			}

			// Validate combine variables
			if patchInfo.Patch.Combine != nil {
				for i, variable := range patchInfo.Patch.Combine.Variables {
					if variable.FromFieldPath == "" {
						continue
					}
					if v.navigator.HasSchema(patchInfo.SourceGVK) {
						validation := v.navigator.ValidatePath(patchInfo.SourceGVK, variable.FromFieldPath)
						if !validation.Valid {
							hasError = true
							invalidPath := InvalidPathInfo{
								CompositionName: patchInfo.CompositionName,
								ResourceName:    patchInfo.ResourceName,
								PatchIndex:      patchInfo.PatchIndex,
								Path:            variable.FromFieldPath,
								PathType:        fmt.Sprintf("combine.variables[%d].fromFieldPath", i),
								Reason:          fmt.Sprintf("%s (at '%s')", validation.Reason, validation.InvalidSegment),
								SourceFile:      patchInfo.SourceFile,
								SourceLine:      patchInfo.SourceLine,
								SourceGVK:       patchInfo.SourceGVK,
								TargetGVK:       patchInfo.TargetGVK,
							}
							result.InvalidPaths = append(result.InvalidPaths, invalidPath)

							location := formatLocation(patchInfo.SourceFile, patchInfo.SourceLine)
							if location != "" {
								if _, err := fmt.Fprintf(w, "[x] %s %s/%s patch[%d]: combine.variables[%d].fromFieldPath '%s' is invalid - %s\n",
									location, patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex, i,
									variable.FromFieldPath, invalidPath.Reason); err != nil {
									return errors.Wrap(err, "cannot write output")
								}
							} else {
								if _, err := fmt.Fprintf(w, "[x] %s/%s patch[%d]: combine.variables[%d].fromFieldPath '%s' is invalid - %s\n",
									patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex, i,
									variable.FromFieldPath, invalidPath.Reason); err != nil {
									return errors.Wrap(err, "cannot write output")
								}
							}
						}
					}
				}
			}

			if hasError {
				result.InvalidPatches++
			} else {
				result.ValidPatches++
			}
		}
	}

	return nil
}

func (v *PatchValidator) detectUnusedParams(w io.Writer, result *PatchValidationResult) error {
	if !v.config.OnlyInvalid {
		if _, err := fmt.Fprintf(w, "\n--- Analyzing Parameter Usage ---\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	analysisResult, err := v.analyzer.Analyze()
	if err != nil {
		return errors.Wrap(err, "cannot analyze parameters")
	}

	result.TotalParameters = analysisResult.TotalParameters
	result.UsedParameters = analysisResult.UsedParameters
	result.UnusedParameters = len(analysisResult.UnusedParameters)
	result.UnusedParams = analysisResult.UnusedParameters

	if len(analysisResult.UnusedParameters) > 0 {
		if _, err := fmt.Fprintf(w, "\n[!] Found %d unused parameters (defined in XRD but never used in patches):\n",
			len(analysisResult.UnusedParameters)); err != nil {
			return errors.Wrap(err, "cannot write output")
		}

		for _, param := range analysisResult.UnusedParameters {
			location := formatLocation(param.SourceFile, param.SourceLine)

			// Build usage info string
			usageInfo := ""
			if param.TotalCompositionsForXRD > 1 {
				usedCount := len(param.UsedInCompositions)
				if usedCount > 0 {
					// Partially used - show which compositions use it
					usageInfo = fmt.Sprintf(" [used in %d/%d compositions: %s]",
						usedCount, param.TotalCompositionsForXRD,
						strings.Join(param.UsedInCompositions, ", "))
				} else {
					usageInfo = fmt.Sprintf(" [unused in all %d compositions]", param.TotalCompositionsForXRD)
				}
			}

			if location != "" && param.XRDName != "" {
				if _, err := fmt.Fprintf(w, "    - %s (XRD: %s @ %s)%s\n", param.Path, param.XRDName, location, usageInfo); err != nil {
					return errors.Wrap(err, "cannot write output")
				}
			} else if param.XRDName != "" {
				if _, err := fmt.Fprintf(w, "    - %s (XRD: %s)%s\n", param.Path, param.XRDName, usageInfo); err != nil {
					return errors.Wrap(err, "cannot write output")
				}
			} else {
				if _, err := fmt.Fprintf(w, "    - %s%s\n", param.Path, usageInfo); err != nil {
					return errors.Wrap(err, "cannot write output")
				}
			}
		}
	} else if !v.config.OnlyInvalid {
		if _, err := fmt.Fprintf(w, "[✓] All %d parameters are used in composition patches\n",
			analysisResult.TotalParameters); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	// Also report on partially used parameters (parent objects where only some children are used)
	if len(analysisResult.PartiallyUsed) > 0 {
		if _, err := fmt.Fprintf(w, "\n[~] Found %d parameter groups with unused children:\n",
			len(analysisResult.PartiallyUsed)); err != nil {
			return errors.Wrap(err, "cannot write output")
		}

		for _, param := range analysisResult.PartiallyUsed {
			if _, err := fmt.Fprintf(w, "    - %s (some child properties unused)\n", param.Path); err != nil {
				return errors.Wrap(err, "cannot write output")
			}
		}
	}

	return nil
}

// validateNestedPath validates a path that goes into a nested resource (e.g., inside manifest).
// Returns true if validation was successful, false otherwise.
func (v *PatchValidator) validateNestedPath(
	comp *ParsedComposition,
	patchInfo PatchInfo,
	parentValidation *PathValidationResult,
	w io.Writer,
	result *PatchValidationResult,
) bool {
	// Find the composed resource
	var composedRes *ComposedResource
	for i := range comp.Resources {
		if comp.Resources[i].Name == patchInfo.ResourceName {
			composedRes = &comp.Resources[i]
			break
		}
	}

	if composedRes == nil || composedRes.Base == nil {
		return false
	}

	// Extract nested resources from the base
	nestedInfos := ExtractNestedResources(composedRes.Base)
	if len(nestedInfos) == 0 {
		return false
	}

	// Check if the path goes into a nested resource
	nestedInfo := IsPathInNestedResource(patchInfo.Patch.ToFieldPath, nestedInfos)
	if nestedInfo == nil {
		return false
	}

	// Get the path inside the nested resource
	nestedPath := GetNestedPath(patchInfo.Patch.ToFieldPath, nestedInfo.ParentPath)
	if nestedPath == "" {
		return false
	}

	// Check if we have a schema for the nested GVK
	if !v.navigator.HasSchema(nestedInfo.NestedGVK) {
		// No schema for nested resource - log info and skip
		return false
	}

	// Validate the nested path
	nestedValidation := v.navigator.ValidatePath(nestedInfo.NestedGVK, nestedPath)
	if !nestedValidation.Valid && !nestedValidation.StoppedAtPreserveUnknown {
		// Error in nested path
		result.InvalidPatches++
		invalidPath := InvalidPathInfo{
			CompositionName: patchInfo.CompositionName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			Path:            patchInfo.Patch.ToFieldPath,
			PathType:        "toFieldPath",
			Reason:          fmt.Sprintf("invalid nested path in %s: %s (at '%s')", nestedInfo.NestedGVK.Kind, nestedValidation.Reason, nestedValidation.InvalidSegment),
			SourceGVK:       patchInfo.SourceGVK,
			TargetGVK:       nestedInfo.NestedGVK,
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
		}
		result.InvalidPaths = append(result.InvalidPaths, invalidPath)

		location := formatLocation(patchInfo.SourceFile, patchInfo.SourceLine)
		if location != "" {
			if _, err := fmt.Fprintf(w, "[x] %s %s/%s patch[%d]: toFieldPath '%s' is invalid - %s\n",
				location, patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
				patchInfo.Patch.ToFieldPath, invalidPath.Reason); err != nil {
				return false
			}
		} else {
			if _, err := fmt.Fprintf(w, "[x] %s/%s patch[%d]: toFieldPath '%s' is invalid - %s\n",
				patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
				patchInfo.Patch.ToFieldPath, invalidPath.Reason); err != nil {
				return false
			}
		}
		return true // We did validate (found an error)
	}

	// Validation successful
	result.ValidPatches++
	return true
}

func (v *PatchValidator) printSummary(w io.Writer, result *PatchValidationResult) error {
	// Determine overall status first
	hasErrors := result.InvalidPatches > 0
	if v.config.StrictMode && result.UnusedParameters > 0 {
		hasErrors = true
	}

	// In OnlyInvalid mode, skip summary if no errors
	if v.config.OnlyInvalid && !hasErrors && result.UnusedParameters == 0 {
		return nil
	}

	if _, err := fmt.Fprintf(w, "\n=== Validation Summary ===\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if _, err := fmt.Fprintf(w, "Compositions analyzed: %d\n", result.CompositionsLoaded); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if v.config.ValidatePatchPaths {
		if _, err := fmt.Fprintf(w, "Patches validated: %d (valid: %d, invalid: %d, skipped: %d)\n",
			result.TotalPatches, result.ValidPatches, result.InvalidPatches, result.SkippedPatches); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	if v.config.DetectUnusedParams {
		if _, err := fmt.Fprintf(w, "Parameters analyzed: %d (used: %d, unused: %d)\n",
			result.TotalParameters, result.UsedParameters, result.UnusedParameters); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	// Print warnings
	if len(result.Warnings) > 0 {
		if _, err := fmt.Fprintf(w, "\nWarnings (%d):\n", len(result.Warnings)); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
		for _, warning := range result.Warnings {
			if _, err := fmt.Fprintf(w, "  [!] %s\n", warning); err != nil {
				return errors.Wrap(err, "cannot write output")
			}
		}
	}

	if hasErrors {
		if _, err := fmt.Fprintf(w, "\n[FAIL] Validation completed with errors\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	} else if !v.config.OnlyInvalid {
		if _, err := fmt.Fprintf(w, "\n[PASS] Validation completed successfully\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	return nil
}

// HasErrors returns true if validation found errors.
func (r *PatchValidationResult) HasErrors() bool {
	return r.InvalidPatches > 0
}

// HasWarnings returns true if validation found warnings.
func (r *PatchValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0 || r.UnusedParameters > 0
}

// CompositionValidation performs comprehensive validation of compositions.
func CompositionValidation(
	extensions []*unstructured.Unstructured,
	crds []*extv1.CustomResourceDefinition,
	config PatchValidationConfig,
	w io.Writer,
) (*PatchValidationResult, error) {
	validator := NewPatchValidator(crds, config)

	// Load compositions from extensions
	if err := validator.LoadCompositions(extensions); err != nil {
		return nil, errors.Wrap(err, "cannot load compositions")
	}

	return validator.Validate(w)
}
