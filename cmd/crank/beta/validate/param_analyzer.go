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
	"sort"
	"strings"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
)

// ParameterUsage represents how a parameter is used.
type ParameterUsage struct {
	Path                    string
	UsedInPatches           []string // List of composition:resource:patch references
	UsedInCompositions      []string // List of composition names that use this parameter
	TotalCompositionsForXRD int      // Total number of compositions implementing this XRD
	IsUsed                  bool
	IsIntermediate          bool   // True if this is an intermediate object (e.g., spec.parameters.aws)
	SourceFile              string // Source XRD file path
	SourceLine              int    // Source line number
	XRDName                 string // Name of the XRD that defines this parameter
}

// isCrossplaneMachineryField returns true if the path is a Crossplane-managed field.
func isCrossplaneMachineryField(path string) bool {
	// These fields are automatically managed by Crossplane runtime, not user patches
	machineryPrefixes := []string{
		"apiVersion",
		"kind",
		"metadata.name",
		"metadata.namespace",
		"metadata.uid",
		"metadata.resourceVersion",
		"metadata.generation",
		"metadata.creationTimestamp",
		"metadata.deletionTimestamp",
		"metadata.deletionGracePeriodSeconds",
		"metadata.labels",
		"metadata.annotations",
		"metadata.ownerReferences",
		"metadata.finalizers",
		"metadata.managedFields",
		"spec.crossplane.compositionRef",
		"spec.crossplane.compositionRevisionRef",
		"spec.crossplane.compositionRevisionSelector",
		"spec.crossplane.compositionSelector",
		"spec.crossplane.compositionUpdatePolicy",
		"spec.crossplane.resourceRefs",
		"spec.crossplane.claimRef",
		"spec.crossplane.environmentConfigRefs",
		"spec.compositionRef",
		"spec.compositionRevisionRef",
		"spec.compositionRevisionSelector",
		"spec.compositionSelector",
		"spec.compositionUpdatePolicy",
		"spec.resourceRefs",
		"spec.claimRef",
		"spec.environmentConfigRefs",
		"spec.writeConnectionSecretToRef",
		"spec.publishConnectionDetailsTo",
		"status.conditions",
		"status.connectionDetails",
	}

	for _, prefix := range machineryPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+".") {
			return true
		}
	}
	return false
}

// ParamAnalysisResult contains the results of parameter usage analysis.
type ParamAnalysisResult struct {
	TotalParameters   int
	UsedParameters    int
	UnusedParameters  []ParameterUsage
	PartiallyUsed     []ParameterUsage // Objects where some children are used but not all
	UsageDetails      map[string]ParameterUsage
	InvalidPatchPaths []InvalidPathInfo
}

// InvalidPathInfo contains information about an invalid patch path.
type InvalidPathInfo struct {
	CompositionName string
	ResourceName    string
	PatchIndex      int
	Path            string
	PathType        string // "fromFieldPath" or "toFieldPath"
	Reason          string
	SourceGVK       schema.GroupVersionKind
	TargetGVK       schema.GroupVersionKind
	SourceFile      string // Source file path
	SourceLine      int    // Source line number
}

// ParamAnalyzer analyzes parameter usage in compositions.
type ParamAnalyzer struct {
	navigator *SchemaNavigator
	parser    *CompositionParser
	crds      []*extv1.CustomResourceDefinition
}

// NewParamAnalyzer creates a new ParamAnalyzer.
func NewParamAnalyzer(crds []*extv1.CustomResourceDefinition, parser *CompositionParser) *ParamAnalyzer {
	return &ParamAnalyzer{
		navigator: NewSchemaNavigator(crds),
		parser:    parser,
		crds:      crds,
	}
}

// Analyze performs comprehensive analysis of parameter usage.
func (a *ParamAnalyzer) Analyze() (*ParamAnalysisResult, error) {
	result := &ParamAnalysisResult{
		UsageDetails:      make(map[string]ParameterUsage),
		UnusedParameters:  make([]ParameterUsage, 0),
		PartiallyUsed:     make([]ParameterUsage, 0),
		InvalidPatchPaths: make([]InvalidPathInfo, 0),
	}

	// Count compositions per XRD (GVK)
	compositionsPerXRD := make(map[string][]string) // GVK string -> list of composition names
	for _, comp := range a.parser.GetCompositions() {
		gvkKey := comp.CompositeTypeRef.String()
		compositionsPerXRD[gvkKey] = append(compositionsPerXRD[gvkKey], comp.Name)
	}

	// For each composition, analyze its patches
	for _, comp := range a.parser.GetCompositions() {
		// Extract all parameter paths from the XRD for this composition
		xrGVK := comp.CompositeTypeRef
		xrdSchema := a.navigator.GetSchemaForGVK(xrGVK)
		if xrdSchema == nil {
			continue
		}

		// Get all spec.parameters.* paths
		paramPaths := ExtractParameterPaths(xrdSchema, "", 10)

		// Get XRD name from GVK
		xrdName := xrGVK.Kind
		gvkKey := xrGVK.String()
		totalCompositions := len(compositionsPerXRD[gvkKey])

		// Initialize usage tracking (filter out machinery fields)
		for _, path := range paramPaths {
			// Skip Crossplane machinery fields - they're managed by runtime, not patches
			if isCrossplaneMachineryField(path) {
				continue
			}

			if _, exists := result.UsageDetails[path]; !exists {
				result.UsageDetails[path] = ParameterUsage{
					Path:                    path,
					UsedInPatches:           make([]string, 0),
					UsedInCompositions:      make([]string, 0),
					TotalCompositionsForXRD: totalCompositions,
					IsUsed:                  false,
					XRDName:                 xrdName,
					SourceFile:              comp.SourceFile, // Use composition source file as reference
					SourceLine:              comp.SourceLine,
				}
			}
		}

		// Validate all patches and track usage
		for _, patchInfo := range comp.AllPatches {
			// Validate fromFieldPath
			if patchInfo.Patch.FromFieldPath != "" {
				a.validateAndTrackPath(patchInfo, "fromFieldPath", patchInfo.Patch.FromFieldPath, result, comp.Name)
			}

			// Validate toFieldPath
			if patchInfo.Patch.ToFieldPath != "" {
				a.validateAndTrackPath(patchInfo, "toFieldPath", patchInfo.Patch.ToFieldPath, result, comp.Name)
			}

			// Validate combine variables
			if patchInfo.Patch.Combine != nil {
				for _, v := range patchInfo.Patch.Combine.Variables {
					if v.FromFieldPath != "" {
						a.validateAndTrackPath(patchInfo, "combine.fromFieldPath", v.FromFieldPath, result, comp.Name)
					}
				}
			}
		}
	}

	// Determine unused parameters
	for path, usage := range result.UsageDetails {
		result.TotalParameters++
		if usage.IsUsed {
			result.UsedParameters++
		} else {
			// Check if this is an intermediate object with used children
			hasUsedChildren := false
			for otherPath, otherUsage := range result.UsageDetails {
				if strings.HasPrefix(otherPath, path+".") && otherUsage.IsUsed {
					hasUsedChildren = true
					break
				}
			}

			if hasUsedChildren {
				usage.IsIntermediate = true
				result.PartiallyUsed = append(result.PartiallyUsed, usage)
			} else {
				result.UnusedParameters = append(result.UnusedParameters, usage)
			}
		}
	}

	// Sort unused parameters for consistent output
	sort.Slice(result.UnusedParameters, func(i, j int) bool {
		return result.UnusedParameters[i].Path < result.UnusedParameters[j].Path
	})

	return result, nil
}

func (a *ParamAnalyzer) validateAndTrackPath(patchInfo PatchInfo, pathType, path string, result *ParamAnalysisResult, compositionName string) {
	// Track usage
	patchRef := fmt.Sprintf("%s:%s:patch[%d]", patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex)

	if usage, exists := result.UsageDetails[path]; exists {
		usage.IsUsed = true
		usage.UsedInPatches = append(usage.UsedInPatches, patchRef)
		// Track which compositions use this parameter (avoid duplicates)
		if !containsString(usage.UsedInCompositions, compositionName) {
			usage.UsedInCompositions = append(usage.UsedInCompositions, compositionName)
		}
		result.UsageDetails[path] = usage
	}

	// Also mark parent paths as used (e.g., if spec.parameters.aws.accountId is used, spec.parameters.aws is also used)
	parts := strings.Split(path, ".")
	for i := 1; i < len(parts); i++ {
		parentPath := strings.Join(parts[:i], ".")
		if usage, exists := result.UsageDetails[parentPath]; exists {
			usage.IsUsed = true
			if !containsString(usage.UsedInCompositions, compositionName) {
				usage.UsedInCompositions = append(usage.UsedInCompositions, compositionName)
			}
			result.UsageDetails[parentPath] = usage
		}
	}

	// Validate the path exists in the schema
	var gvk schema.GroupVersionKind
	if pathType == "fromFieldPath" || pathType == "combine.fromFieldPath" {
		gvk = patchInfo.SourceGVK
	} else {
		gvk = patchInfo.TargetGVK
	}

	// Only validate if we have a schema for this GVK
	if !a.navigator.HasSchema(gvk) {
		return
	}

	validation := a.navigator.ValidatePath(gvk, path)
	if !validation.Valid {
		result.InvalidPatchPaths = append(result.InvalidPatchPaths, InvalidPathInfo{
			CompositionName: patchInfo.CompositionName,
			ResourceName:    patchInfo.ResourceName,
			PatchIndex:      patchInfo.PatchIndex,
			Path:            path,
			PathType:        pathType,
			Reason:          fmt.Sprintf("%s (at '%s')", validation.Reason, validation.InvalidSegment),
			SourceGVK:       patchInfo.SourceGVK,
			TargetGVK:       patchInfo.TargetGVK,
			SourceFile:      patchInfo.SourceFile,
			SourceLine:      patchInfo.SourceLine,
		})
	}
}

// containsString checks if a slice contains a string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// ValidateAllPatches performs comprehensive patch validation.
func (a *ParamAnalyzer) ValidateAllPatches(w io.Writer) (int, int, error) {
	validCount := 0
	invalidCount := 0

	for _, comp := range a.parser.GetCompositions() {
		for _, patchInfo := range comp.AllPatches {
			valid, err := a.validatePatch(patchInfo, w)
			if err != nil {
				return validCount, invalidCount, err
			}
			if valid {
				validCount++
			} else {
				invalidCount++
			}
		}
	}

	return validCount, invalidCount, nil
}

func (a *ParamAnalyzer) validatePatch(patchInfo PatchInfo, w io.Writer) (bool, error) {
	allValid := true

	// Validate fromFieldPath against source schema
	if patchInfo.Patch.FromFieldPath != "" {
		if a.navigator.HasSchema(patchInfo.SourceGVK) {
			result := a.navigator.ValidatePath(patchInfo.SourceGVK, patchInfo.Patch.FromFieldPath)
			if !result.Valid {
				allValid = false
				if _, err := fmt.Fprintf(w, "[x] invalid patch path in %s/%s patch[%d]: fromFieldPath '%s' - %s (at '%s')\n",
					patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
					patchInfo.Patch.FromFieldPath, result.Reason, result.InvalidSegment); err != nil {
					return false, errors.Wrap(err, "cannot write output")
				}
			}
		}
	}

	// Validate toFieldPath against target schema
	if patchInfo.Patch.ToFieldPath != "" {
		if a.navigator.HasSchema(patchInfo.TargetGVK) {
			result := a.navigator.ValidatePath(patchInfo.TargetGVK, patchInfo.Patch.ToFieldPath)
			if !result.Valid {
				allValid = false
				if _, err := fmt.Fprintf(w, "[x] invalid patch path in %s/%s patch[%d]: toFieldPath '%s' - %s (at '%s')\n",
					patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex,
					patchInfo.Patch.ToFieldPath, result.Reason, result.InvalidSegment); err != nil {
					return false, errors.Wrap(err, "cannot write output")
				}
			}
		}
	}

	// Validate combine variables
	if patchInfo.Patch.Combine != nil {
		for i, v := range patchInfo.Patch.Combine.Variables {
			if v.FromFieldPath == "" {
				continue
			}
			if a.navigator.HasSchema(patchInfo.SourceGVK) {
				result := a.navigator.ValidatePath(patchInfo.SourceGVK, v.FromFieldPath)
				if !result.Valid {
					allValid = false
					if _, err := fmt.Fprintf(w, "[x] invalid patch path in %s/%s patch[%d]: combine.variables[%d].fromFieldPath '%s' - %s (at '%s')\n",
						patchInfo.CompositionName, patchInfo.ResourceName, patchInfo.PatchIndex, i,
						v.FromFieldPath, result.Reason, result.InvalidSegment); err != nil {
						return false, errors.Wrap(err, "cannot write output")
					}
				}
			}
		}
	}

	return allValid, nil
}

// PrintUnusedParameters prints a report of unused parameters.
func PrintUnusedParameters(result *ParamAnalysisResult, w io.Writer) error {
	if len(result.UnusedParameters) == 0 {
		if _, err := fmt.Fprintln(w, "[✓] All parameters are used in composition patches"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
		return nil
	}

	if _, err := fmt.Fprintf(w, "\n[!] Found %d unused parameters:\n", len(result.UnusedParameters)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	for _, param := range result.UnusedParameters {
		if _, err := fmt.Fprintf(w, "    - %s\n", param.Path); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	return nil
}

// PrintInvalidPaths prints a report of invalid patch paths.
func PrintInvalidPaths(result *ParamAnalysisResult, w io.Writer) error {
	if len(result.InvalidPatchPaths) == 0 {
		return nil
	}

	if _, err := fmt.Fprintf(w, "\n[x] Found %d invalid patch paths:\n", len(result.InvalidPatchPaths)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	for _, invalid := range result.InvalidPatchPaths {
		if _, err := fmt.Fprintf(w, "    - %s/%s patch[%d] %s: '%s' - %s\n",
			invalid.CompositionName, invalid.ResourceName, invalid.PatchIndex,
			invalid.PathType, invalid.Path, invalid.Reason); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	return nil
}

// PrintAnalysisSummary prints a summary of the analysis.
func PrintAnalysisSummary(result *ParamAnalysisResult, w io.Writer) error {
	if _, err := fmt.Fprintf(w, "\nParameter Analysis Summary:\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if _, err := fmt.Fprintf(w, "  Total parameters: %d\n", result.TotalParameters); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if _, err := fmt.Fprintf(w, "  Used parameters: %d\n", result.UsedParameters); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if _, err := fmt.Fprintf(w, "  Unused parameters: %d\n", len(result.UnusedParameters)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if _, err := fmt.Fprintf(w, "  Invalid patch paths: %d\n", len(result.InvalidPatchPaths)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	return nil
}
