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
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// PatchedFieldsCollector collects all fields that are patched in a composition resource.
type PatchedFieldsCollector struct {
	// patchedFields maps resource names to their patched field paths
	patchedFields map[string]map[string]bool
}

// NewPatchedFieldsCollector creates a new PatchedFieldsCollector.
func NewPatchedFieldsCollector() *PatchedFieldsCollector {
	return &PatchedFieldsCollector{
		patchedFields: make(map[string]map[string]bool),
	}
}

// CollectFromComposition collects all patched fields from a parsed composition.
func (c *PatchedFieldsCollector) CollectFromComposition(comp *ParsedComposition) {
	// First, build a map of patchSets for quick lookup
	// We need to get patchSets from the AllPatches which includes resolved patches
	// But we should also track PatchSet references
	
	for _, res := range comp.Resources {
		if _, exists := c.patchedFields[res.Name]; !exists {
			c.patchedFields[res.Name] = make(map[string]bool)
		}

		for _, patch := range res.Patches {
			// Collect toFieldPath - this is where the value goes
			if patch.ToFieldPath != "" {
				c.addPatchedPath(res.Name, patch.ToFieldPath)
			}
		}
	}

	// Also collect from AllPatches which includes resolved PatchSet patches
	for _, patchInfo := range comp.AllPatches {
		if _, exists := c.patchedFields[patchInfo.ResourceName]; !exists {
			c.patchedFields[patchInfo.ResourceName] = make(map[string]bool)
		}

		if patchInfo.Patch.ToFieldPath != "" {
			c.addPatchedPath(patchInfo.ResourceName, patchInfo.Patch.ToFieldPath)
		}
	}
}

// addPatchedPath adds a path and all its prefixes to the patched fields.
func (c *PatchedFieldsCollector) addPatchedPath(resourceName, path string) {
	fields := c.patchedFields[resourceName]
	if fields == nil {
		fields = make(map[string]bool)
		c.patchedFields[resourceName] = fields
	}

	// Add the exact path
	fields[path] = true

	// Also add all parent paths (a patch to spec.forProvider.region means spec.forProvider is also "touched")
	parts := strings.Split(path, ".")
	for i := 1; i < len(parts); i++ {
		parentPath := strings.Join(parts[:i], ".")
		fields[parentPath] = true
	}
}

// IsFieldPatched checks if a field is patched in a resource.
func (c *PatchedFieldsCollector) IsFieldPatched(resourceName, fieldPath string) bool {
	fields, exists := c.patchedFields[resourceName]
	if !exists {
		return false
	}

	// Check exact match
	if fields[fieldPath] {
		return true
	}

	// Check if any patch targets a child of this field
	// e.g., if fieldPath is "spec.forProvider" and there's a patch to "spec.forProvider.region"
	for patchedPath := range fields {
		if strings.HasPrefix(patchedPath, fieldPath+".") {
			return true
		}
		if strings.HasPrefix(patchedPath, fieldPath+"[") {
			return true
		}
	}

	return false
}

// FilterRequiredFieldErrors filters out "Required value" errors for fields that are patched.
func FilterRequiredFieldErrors(errors field.ErrorList, resourceName string, collector *PatchedFieldsCollector) field.ErrorList {
	if collector == nil {
		return errors
	}

	filtered := make(field.ErrorList, 0, len(errors))
	for _, err := range errors {
		// Check if this is a "Required value" error
		if err.Type == field.ErrorTypeRequired {
			// Convert field path to string (remove leading dot if present)
			fieldPath := strings.TrimPrefix(err.Field, ".")

			// Check if this field is patched
			if collector.IsFieldPatched(resourceName, fieldPath) {
				// Skip this error - the field will be patched in
				continue
			}
		}

		filtered = append(filtered, err)
	}

	return filtered
}

// IsCELRequiredError checks if a CEL error is about a required field.
func IsCELRequiredError(err *field.Error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "is a required parameter") ||
		strings.Contains(errStr, "Required value")
}

// ExtractRequiredFieldFromCEL extracts the field path from a CEL required error.
// e.g., "spec.forProvider.location is a required parameter" -> "spec.forProvider.location"
func ExtractRequiredFieldFromCEL(err *field.Error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()

	// Look for pattern "X is a required parameter"
	if idx := strings.Index(errStr, " is a required parameter"); idx > 0 {
		// Find the field path (last word before " is a required parameter")
		prefix := errStr[:idx]
		// Find the start of the field path
		parts := strings.Split(prefix, " ")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}

	return ""
}
