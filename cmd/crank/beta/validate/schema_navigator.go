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
	"regexp"
	"strconv"
	"strings"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// PathValidationResult represents the result of validating a field path.
type PathValidationResult struct {
	Valid                    bool
	Path                     string
	InvalidSegment           string
	Reason                   string
	SchemaType               string // The type at the path if valid
	IsWildcard               bool   // True if path contains wildcards like [*]
	StoppedAtPreserveUnknown bool   // True if validation stopped at x-kubernetes-preserve-unknown-fields
	ValidatedUpTo            string // The path prefix that was validated before hitting preserve-unknown-fields
}

// SchemaNavigator validates field paths against OpenAPI schemas.
type SchemaNavigator struct {
	schemas map[schema.GroupVersionKind]*extv1.JSONSchemaProps
}

// NewSchemaNavigator creates a new SchemaNavigator from CRDs.
func NewSchemaNavigator(crds []*extv1.CustomResourceDefinition) *SchemaNavigator {
	nav := &SchemaNavigator{
		schemas: make(map[schema.GroupVersionKind]*extv1.JSONSchemaProps),
	}

	for _, crd := range crds {
		for _, version := range crd.Spec.Versions {
			if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
				continue
			}

			gvk := schema.GroupVersionKind{
				Group:   crd.Spec.Group,
				Version: version.Name,
				Kind:    crd.Spec.Names.Kind,
			}

			nav.schemas[gvk] = version.Schema.OpenAPIV3Schema
		}
	}

	return nav
}

// objectMetaSchema is the K8s ObjectMeta schema for validating metadata paths.
// This is derived from the official K8s ObjectMeta definition.
var objectMetaSchema = &extv1.JSONSchemaProps{
	Type: "object",
	Properties: map[string]extv1.JSONSchemaProps{
		"name":                       {Type: "string"},
		"namespace":                  {Type: "string"},
		"generateName":               {Type: "string"},
		"uid":                        {Type: "string"},
		"resourceVersion":            {Type: "string"},
		"generation":                 {Type: "integer", Format: "int64"},
		"selfLink":                   {Type: "string"},
		"creationTimestamp":          {Type: "string", Format: "date-time"},
		"deletionTimestamp":          {Type: "string", Format: "date-time"},
		"deletionGracePeriodSeconds": {Type: "integer", Format: "int64"},
		"labels": {
			Type: "object",
			AdditionalProperties: &extv1.JSONSchemaPropsOrBool{
				Allows: true,
				Schema: &extv1.JSONSchemaProps{Type: "string"},
			},
		},
		"annotations": {
			Type: "object",
			AdditionalProperties: &extv1.JSONSchemaPropsOrBool{
				Allows: true,
				Schema: &extv1.JSONSchemaProps{Type: "string"},
			},
		},
		"finalizers": {
			Type: "array",
			Items: &extv1.JSONSchemaPropsOrArray{
				Schema: &extv1.JSONSchemaProps{Type: "string"},
			},
		},
		"ownerReferences": {
			Type: "array",
			Items: &extv1.JSONSchemaPropsOrArray{
				Schema: &extv1.JSONSchemaProps{
					Type: "object",
					Properties: map[string]extv1.JSONSchemaProps{
						"apiVersion":         {Type: "string"},
						"kind":               {Type: "string"},
						"name":               {Type: "string"},
						"uid":                {Type: "string"},
						"controller":         {Type: "boolean"},
						"blockOwnerDeletion": {Type: "boolean"},
					},
					Required: []string{"apiVersion", "kind", "name", "uid"},
				},
			},
		},
		"managedFields": {
			Type: "array",
			Items: &extv1.JSONSchemaPropsOrArray{
				Schema: &extv1.JSONSchemaProps{
					Type: "object",
					Properties: map[string]extv1.JSONSchemaProps{
						"manager":     {Type: "string"},
						"operation":   {Type: "string"},
						"apiVersion":  {Type: "string"},
						"time":        {Type: "string", Format: "date-time"},
						"fieldsType":  {Type: "string"},
						"fieldsV1":    {Type: "object"},
						"subresource": {Type: "string"},
					},
				},
			},
		},
	},
}

// ValidatePath validates that a field path exists in the schema for the given GVK.
func (n *SchemaNavigator) ValidatePath(gvk schema.GroupVersionKind, path string) PathValidationResult {
	result := PathValidationResult{
		Path: path,
	}

	// Handle apiVersion and kind - they're just strings, no sub-paths allowed
	if path == "apiVersion" || path == "kind" {
		result.Valid = true
		result.SchemaType = "string"
		return result
	}
	if strings.HasPrefix(path, "apiVersion.") || strings.HasPrefix(path, "kind.") {
		result.InvalidSegment = strings.Split(path, ".")[1]
		result.Reason = "cannot access sub-fields of string type"
		return result
	}

	// Handle metadata paths - validate against K8s ObjectMeta schema
	if path == "metadata" {
		result.Valid = true
		result.SchemaType = "object"
		return result
	}
	if strings.HasPrefix(path, "metadata.") || strings.HasPrefix(path, "metadata[") {
		// Strip "metadata." and validate the rest against ObjectMeta schema
		subPath := strings.TrimPrefix(path, "metadata.")
		if strings.HasPrefix(path, "metadata[") {
			subPath = strings.TrimPrefix(path, "metadata")
		}
		return n.validatePathAgainstSchema(objectMetaSchema, subPath, "metadata")
	}

	schemaProps, ok := n.schemas[gvk]
	if !ok {
		result.Reason = "no schema found for GVK"
		return result
	}

	segments := parseFieldPath(path)
	if len(segments) == 0 {
		result.Valid = true
		result.SchemaType = schemaProps.Type
		return result
	}

	currentSchema := schemaProps

	for i, segment := range segments {
		if segment.IsArrayIndex || segment.IsWildcard {
			result.IsWildcard = result.IsWildcard || segment.IsWildcard

			// For array access, we need to check the items schema
			if currentSchema.Type == "array" {
				if currentSchema.Items == nil || currentSchema.Items.Schema == nil {
					result.InvalidSegment = segment.Raw
					result.Reason = "array has no items schema"
					return result
				}
				currentSchema = currentSchema.Items.Schema
				continue
			}

			// Could also be a map with additional properties
			if currentSchema.AdditionalProperties != nil && currentSchema.AdditionalProperties.Schema != nil {
				currentSchema = currentSchema.AdditionalProperties.Schema
				continue
			}

			// Also check x-kubernetes-preserve-unknown-fields
			if currentSchema.XPreserveUnknownFields != nil && *currentSchema.XPreserveUnknownFields {
				// Validation stopped at preserve-unknown-fields
				result.Valid = true
				result.StoppedAtPreserveUnknown = true
				result.ValidatedUpTo = buildPathFromSegments(segments[:i])
				result.SchemaType = "unknown"
				return result
			}

			result.InvalidSegment = segment.Raw
			result.Reason = "cannot index into non-array/non-map type"
			return result
		}

		// Regular field access
		fieldName := segment.FieldName

		// Check if it's a map key access like metadata.labels[key]
		if strings.Contains(fieldName, "[") {
			// Parse the field name and key
			parts := strings.SplitN(fieldName, "[", 2)
			fieldName = parts[0]

			// After we access the field, we'll need to handle the map key
			if len(parts) > 1 {
				// We have a map key access
				// First, navigate to the field
				if currentSchema.Properties == nil {
					if currentSchema.XPreserveUnknownFields != nil && *currentSchema.XPreserveUnknownFields {
						result.Valid = true
						result.SchemaType = "unknown"
						return result
					}
					result.InvalidSegment = fieldName
					result.Reason = "schema has no properties"
					return result
				}

				fieldSchema, ok := currentSchema.Properties[fieldName]
				if !ok {
					result.InvalidSegment = fieldName
					result.Reason = "field not found in schema"
					return result
				}

				// Now we need to handle the map key access
				// Maps in Kubernetes use additionalProperties
				if fieldSchema.AdditionalProperties != nil && fieldSchema.AdditionalProperties.Schema != nil {
					currentSchema = fieldSchema.AdditionalProperties.Schema
					continue
				}

				// Also check x-kubernetes-preserve-unknown-fields
				if fieldSchema.XPreserveUnknownFields != nil && *fieldSchema.XPreserveUnknownFields {
					result.Valid = true
					result.StoppedAtPreserveUnknown = true
					result.ValidatedUpTo = buildPathFromSegments(segments[:i+1])
					result.SchemaType = "unknown"
					return result
				}

				// Check if it's an object with type=object (common for labels/annotations)
				if fieldSchema.Type == "object" {
					// Assume it's a map, allow the key access
					result.Valid = true
					result.SchemaType = "string" // Labels/annotations are typically strings
					return result
				}

				result.InvalidSegment = segment.Raw
				result.Reason = "cannot access key on non-map type"
				return result
			}
		}

		// Standard property access
		if currentSchema.Properties == nil {
			// Check x-kubernetes-preserve-unknown-fields
			if currentSchema.XPreserveUnknownFields != nil && *currentSchema.XPreserveUnknownFields {
				result.Valid = true
				result.StoppedAtPreserveUnknown = true
				result.ValidatedUpTo = buildPathFromSegments(segments[:i])
				result.SchemaType = "unknown"
				return result
			}

			// Check additionalProperties for map-like objects
			if currentSchema.Type == "object" && currentSchema.AdditionalProperties != nil {
				if currentSchema.AdditionalProperties.Schema != nil {
					currentSchema = currentSchema.AdditionalProperties.Schema
					continue
				}
			}

			result.InvalidSegment = fieldName
			result.Reason = "schema has no properties"
			return result
		}

		fieldSchema, ok := currentSchema.Properties[fieldName]
		if !ok {
			// Check x-kubernetes-preserve-unknown-fields
			if currentSchema.XPreserveUnknownFields != nil && *currentSchema.XPreserveUnknownFields {
				result.Valid = true
				result.StoppedAtPreserveUnknown = true
				result.ValidatedUpTo = buildPathFromSegments(segments[:i])
				result.SchemaType = "unknown"
				return result
			}

			// Check additionalProperties
			if currentSchema.AdditionalProperties != nil && currentSchema.AdditionalProperties.Schema != nil {
				currentSchema = currentSchema.AdditionalProperties.Schema
				continue
			}

			result.InvalidSegment = fieldName
			result.Reason = "field not found in schema"
			return result
		}

		currentSchema = &fieldSchema

		// If this is the last segment, record the type
		if i == len(segments)-1 {
			result.Valid = true
			result.SchemaType = currentSchema.Type
		}
	}

	result.Valid = true
	result.SchemaType = currentSchema.Type
	return result
}

// GetAllPaths returns all valid paths for a GVK (useful for suggestions).
func (n *SchemaNavigator) GetAllPaths(gvk schema.GroupVersionKind, maxDepth int) []string {
	schemaProps, ok := n.schemas[gvk]
	if !ok {
		return nil
	}

	paths := make([]string, 0)
	n.collectPaths(schemaProps, "", maxDepth, &paths)
	return paths
}

func (n *SchemaNavigator) collectPaths(schema *extv1.JSONSchemaProps, prefix string, maxDepth int, paths *[]string) {
	if maxDepth <= 0 {
		return
	}

	if schema.Properties != nil {
		for name, prop := range schema.Properties {
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			*paths = append(*paths, path)

			// Recursively collect nested paths
			propCopy := prop
			n.collectPaths(&propCopy, path, maxDepth-1, paths)
		}
	}

	// Handle arrays
	if schema.Type == "array" && schema.Items != nil && schema.Items.Schema != nil {
		arrayPath := prefix + "[*]"
		*paths = append(*paths, arrayPath)
		n.collectPaths(schema.Items.Schema, arrayPath, maxDepth-1, paths)
	}
}

// HasSchema checks if a schema exists for the given GVK.
func (n *SchemaNavigator) HasSchema(gvk schema.GroupVersionKind) bool {
	_, ok := n.schemas[gvk]
	return ok
}

// GetSchemaForGVK returns the schema for a GVK if it exists.
func (n *SchemaNavigator) GetSchemaForGVK(gvk schema.GroupVersionKind) *extv1.JSONSchemaProps {
	return n.schemas[gvk]
}

// PathSegment represents a segment of a field path.
type PathSegment struct {
	FieldName    string
	IsArrayIndex bool
	ArrayIndex   int
	IsWildcard   bool
	Raw          string
}

// parseFieldPath parses a field path like "spec.parameters.region" or "status.conditions[0].type".
func parseFieldPath(path string) []PathSegment {
	if path == "" {
		return nil
	}

	segments := make([]PathSegment, 0)

	// Regular expression to match field names and array indices
	// Handles: field, field[0], field[*], field["key"], field[key]
	re := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*|\[\d+\]|\[\*\]|\[[^\]]+\])`)
	matches := re.FindAllString(path, -1)

	for _, match := range matches {
		segment := PathSegment{Raw: match}

		if strings.HasPrefix(match, "[") && strings.HasSuffix(match, "]") {
			inner := match[1 : len(match)-1]

			if inner == "*" {
				segment.IsWildcard = true
				segment.IsArrayIndex = true
			} else if idx, err := strconv.Atoi(inner); err == nil {
				segment.IsArrayIndex = true
				segment.ArrayIndex = idx
			} else {
				// It's a map key like ["key"] or [key]
				segment.FieldName = strings.Trim(inner, "\"'")
			}
		} else {
			segment.FieldName = match
		}

		segments = append(segments, segment)
	}

	return segments
}

// buildPathFromSegments reconstructs a path string from segments.
func buildPathFromSegments(segments []PathSegment) string {
	if len(segments) == 0 {
		return ""
	}

	var parts []string
	for _, seg := range segments {
		if seg.IsArrayIndex || seg.IsWildcard {
			// Array indices are appended to the last field
			if len(parts) > 0 {
				parts[len(parts)-1] += seg.Raw
			} else {
				parts = append(parts, seg.Raw)
			}
		} else if seg.FieldName != "" {
			parts = append(parts, seg.FieldName)
		}
	}

	return strings.Join(parts, ".")
}

// ExtractParameterPaths extracts all parameter paths from an XRD schema.
// It returns paths like "spec.parameters.region", "spec.parameters.nodePool.minSize", etc.
func ExtractParameterPaths(schema *extv1.JSONSchemaProps, prefix string, maxDepth int) []string {
	if schema == nil || maxDepth <= 0 {
		return nil
	}

	paths := make([]string, 0)

	if schema.Properties != nil {
		for name, prop := range schema.Properties {
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}

			// Only collect leaf nodes or nodes that could be patched
			propCopy := prop
			if propCopy.Properties == nil && propCopy.Type != "array" {
				// It's a leaf node
				paths = append(paths, path)
			} else {
				// Include intermediate objects too (they can be patched as a whole)
				paths = append(paths, path)
				// Recurse into nested properties
				paths = append(paths, ExtractParameterPaths(&propCopy, path, maxDepth-1)...)
			}
		}
	}

	// Handle arrays
	if schema.Type == "array" && schema.Items != nil && schema.Items.Schema != nil {
		// Arrays can be patched as a whole
		if prefix != "" {
			paths = append(paths, prefix)
		}
	}

	return paths
}

// validatePathAgainstSchema validates a sub-path against a specific schema.
// prefix is used for error reporting (e.g., "metadata" so errors show "metadata.pica").
func (n *SchemaNavigator) validatePathAgainstSchema(schema *extv1.JSONSchemaProps, path string, prefix string) PathValidationResult {
	result := PathValidationResult{
		Path: prefix + "." + path,
	}

	if path == "" {
		result.Valid = true
		result.SchemaType = schema.Type
		return result
	}

	segments := parseFieldPath(path)
	if len(segments) == 0 {
		result.Valid = true
		result.SchemaType = schema.Type
		return result
	}

	currentSchema := schema

	for i, segment := range segments {
		if segment.IsArrayIndex || segment.IsWildcard {
			// For array access, check the items schema
			if currentSchema.Type == "array" {
				if currentSchema.Items == nil || currentSchema.Items.Schema == nil {
					result.InvalidSegment = segment.Raw
					result.Reason = "array has no items schema"
					return result
				}
				currentSchema = currentSchema.Items.Schema
				continue
			}

			// Could also be a map with additional properties (like labels["key"])
			if currentSchema.AdditionalProperties != nil && currentSchema.AdditionalProperties.Schema != nil {
				currentSchema = currentSchema.AdditionalProperties.Schema
				continue
			}

			// Check if AdditionalProperties allows any value
			if currentSchema.AdditionalProperties != nil && currentSchema.AdditionalProperties.Allows {
				result.Valid = true
				result.SchemaType = "string" // labels/annotations are string maps
				return result
			}

			result.InvalidSegment = segment.Raw
			result.Reason = "cannot index into non-array/non-map type"
			return result
		}

		// Regular field access
		fieldName := segment.FieldName

		if currentSchema.Properties == nil {
			// Check for additional properties (map types like labels, annotations)
			if currentSchema.AdditionalProperties != nil {
				if currentSchema.AdditionalProperties.Schema != nil {
					currentSchema = currentSchema.AdditionalProperties.Schema
					continue
				}
				if currentSchema.AdditionalProperties.Allows {
					result.Valid = true
					result.SchemaType = "string"
					return result
				}
			}

			result.InvalidSegment = fieldName
			result.Reason = "field not found in schema"
			return result
		}

		nextSchema, exists := currentSchema.Properties[fieldName]
		if !exists {
			// Check additional properties as fallback
			if currentSchema.AdditionalProperties != nil && currentSchema.AdditionalProperties.Allows {
				result.Valid = true
				result.SchemaType = "unknown"
				return result
			}

			result.InvalidSegment = fieldName
			result.Reason = "field not found in schema"
			return result
		}

		// If this is the last segment, we're done
		if i == len(segments)-1 {
			result.Valid = true
			result.SchemaType = nextSchema.Type
			return result
		}

		currentSchema = &nextSchema
	}

	result.Valid = true
	result.SchemaType = currentSchema.Type
	return result
}

// SchemaMismatchField represents a field that exists in source but not in target schema.
type SchemaMismatchField struct {
	Path       string // Full path to the field (e.g., "osSku", "nested.field")
	SourceType string // Type in source schema
}

// CompareObjectSchemas compares source and target schemas and returns fields that exist
// in the source but not in the target. This is useful for validating object-to-object patches
// where the entire object is copied from source to target.
// The basePath parameter is the path to the object being compared (e.g., "spec.parameters.azure.nodePool").
func (n *SchemaNavigator) CompareObjectSchemas(sourceGVK, targetGVK schema.GroupVersionKind, basePath string) []SchemaMismatchField {
	sourceSchema := n.GetSchemaForGVK(sourceGVK)
	targetSchema := n.GetSchemaForGVK(targetGVK)

	if sourceSchema == nil || targetSchema == nil {
		return nil
	}

	// Navigate to the base path in both schemas
	sourceAtPath := n.getSchemaAtPath(sourceSchema, basePath)
	targetAtPath := n.getSchemaAtPath(targetSchema, basePath)

	if sourceAtPath == nil || targetAtPath == nil {
		return nil
	}

	// Only compare if both are objects
	if sourceAtPath.Type != "object" || targetAtPath.Type != "object" {
		return nil
	}

	// Compare properties recursively
	var mismatches []SchemaMismatchField
	n.compareSchemaProperties(sourceAtPath, targetAtPath, "", &mismatches, 10)

	return mismatches
}

// getSchemaAtPath navigates to the schema at the given path.
func (n *SchemaNavigator) getSchemaAtPath(schema *extv1.JSONSchemaProps, path string) *extv1.JSONSchemaProps {
	if schema == nil || path == "" {
		return schema
	}

	segments := parseFieldPath(path)
	current := schema

	for _, seg := range segments {
		if current == nil {
			return nil
		}

		if seg.FieldName != "" {
			if current.Properties != nil {
				if prop, ok := current.Properties[seg.FieldName]; ok {
					current = &prop
					continue
				}
			}
			// Field not found
			return nil
		}

		if seg.IsArrayIndex || seg.IsWildcard {
			if current.Items != nil && current.Items.Schema != nil {
				current = current.Items.Schema
				continue
			}
			return nil
		}
	}

	return current
}

// compareSchemaProperties recursively compares properties between source and target schemas.
func (n *SchemaNavigator) compareSchemaProperties(source, target *extv1.JSONSchemaProps, prefix string, mismatches *[]SchemaMismatchField, maxDepth int) {
	if source == nil || target == nil || maxDepth <= 0 {
		return
	}

	// Check if target has x-kubernetes-preserve-unknown-fields - if so, all fields are allowed
	if target.XPreserveUnknownFields != nil && *target.XPreserveUnknownFields {
		return
	}

	// Compare properties
	if source.Properties != nil {
		for name, sourceProp := range source.Properties {
			fieldPath := name
			if prefix != "" {
				fieldPath = prefix + "." + name
			}

			// Check if target has this property
			var targetProp *extv1.JSONSchemaProps
			if target.Properties != nil {
				if prop, ok := target.Properties[name]; ok {
					targetProp = &prop
				}
			}

			if targetProp == nil {
				// Check if target allows additional properties
				if target.AdditionalProperties != nil && target.AdditionalProperties.Allows {
					continue
				}
				// Field exists in source but not in target
				*mismatches = append(*mismatches, SchemaMismatchField{
					Path:       fieldPath,
					SourceType: sourceProp.Type,
				})
				continue
			}

			// If both are objects, recurse
			if sourceProp.Type == "object" && targetProp.Type == "object" {
				n.compareSchemaProperties(&sourceProp, targetProp, fieldPath, mismatches, maxDepth-1)
			}
		}
	}
}
