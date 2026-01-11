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
	"context"
	"fmt"
	"io"

	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	runtimeschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"

	"github.com/crossplane/crossplane/v2/cmd/crank/common/load"
	"github.com/crossplane/crossplane/v2/internal/xcrd"
)

const (
	errWriteOutput = "cannot write output"
)

func newValidatorsAndStructurals(crds []*extv1.CustomResourceDefinition) (map[runtimeschema.GroupVersionKind][]*validation.SchemaValidator, map[runtimeschema.GroupVersionKind]*schema.Structural, error) {
	validators := map[runtimeschema.GroupVersionKind][]*validation.SchemaValidator{}
	structurals := map[runtimeschema.GroupVersionKind]*schema.Structural{}

	for i := range crds {
		internal := &ext.CustomResourceDefinition{}
		if err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(crds[i], internal, nil); err != nil {
			return nil, nil, err
		}

		// Top-level and per-version schemas are mutually exclusive.
		for _, ver := range internal.Spec.Versions {
			var (
				sv  validation.SchemaValidator
				err error
			)

			gvk := runtimeschema.GroupVersionKind{
				Group:   internal.Spec.Group,
				Version: ver.Name,
				Kind:    internal.Spec.Names.Kind,
			}

			var s *ext.JSONSchemaProps

			switch {
			case internal.Spec.Validation != nil:
				s = internal.Spec.Validation.OpenAPIV3Schema
			case ver.Schema != nil && ver.Schema.OpenAPIV3Schema != nil:
				s = ver.Schema.OpenAPIV3Schema
			default:
				// TODO log a warning here, it should never happen
				continue
			}

			sv, _, err = validation.NewSchemaValidator(s)
			if err != nil {
				return nil, nil, err
			}

			validators[gvk] = append(validators[gvk], &sv)

			structural, err := schema.NewStructural(s)
			if err != nil {
				return nil, nil, err
			}

			structurals[gvk] = structural
		}
	}

	return validators, structurals, nil
}

// SchemaValidation validates the resources against the given CRDs.
func SchemaValidation(ctx context.Context, resources []*unstructured.Unstructured, crds []*extv1.CustomResourceDefinition, errorOnMissingSchemas bool, skipSuccessLogs bool, w io.Writer) error {
	return SchemaValidationWithPatches(ctx, resources, crds, errorOnMissingSchemas, skipSuccessLogs, nil, w)
}

// SchemaValidationWithPatches validates resources with awareness of patches that fill required fields.
func SchemaValidationWithPatches(ctx context.Context, resources []*unstructured.Unstructured, crds []*extv1.CustomResourceDefinition, errorOnMissingSchemas bool, skipSuccessLogs bool, patchCollector *PatchedFieldsCollector, w io.Writer) error { //nolint:gocognit // printing the output increases the cyclomatic complexity a little bit
	schemaValidators, structurals, err := newValidatorsAndStructurals(crds)
	if err != nil {
		return errors.Wrap(err, "cannot create schema validators")
	}

	failure, missingSchemas := 0, 0
	missingGVKs := make(map[string]int) // Track which GVKs are missing and how many times

	for _, r := range resources {
		gvk := r.GetObjectKind().GroupVersionKind()
		sv, ok := schemaValidators[gvk]
		s := structurals[gvk] // if we have a schema validator, we should also have a structural

		if !ok {
			missingSchemas++
			gvkStr := r.GroupVersionKind().String()
			missingGVKs[gvkStr]++
			continue
		}

		if err := applyDefaults(r, gvk, crds); err != nil {
			if _, err := fmt.Fprintf(w, "[!] failed to apply defaults for %s, %s: %v\n", r.GroupVersionKind().String(), getResourceName(r), err); err != nil {
				return errors.Wrap(err, errWriteOutput)
			}
		}

		// Get source location for better error messages
		sourceFile := load.GetSourceFile(r)
		sourceLine := load.GetSourceLine(r)

		// Get base resource name from annotation (if this is a base resource extracted from composition)
		baseResourceName := ""
		if annotations := r.GetAnnotations(); annotations != nil {
			baseResourceName = annotations["crossplane.io/base-resource-name"]
		}

		rf := 0
		for _, v := range sv {
			schemaErrors := validation.ValidateCustomResource(nil, r, *v)
			unknownFieldErrors := validateUnknownFields(r.UnstructuredContent(), s)

			// Combine errors
			allErrors := append(schemaErrors, unknownFieldErrors...)

			// Filter out required field errors if this is a base resource with patches
			if patchCollector != nil && baseResourceName != "" {
				allErrors = FilterRequiredFieldErrors(allErrors, baseResourceName, patchCollector)
			}

			for _, e := range allErrors {
				rf++

				// Try to find the exact line using the error path
				errorLine := sourceLine
				if sourceFile != "" && e.Field != "" {
					exactLine := load.FindPathInYAML(sourceFile, sourceLine, e.Field)
					if exactLine > 0 {
						errorLine = exactLine
					}
				}

				if sourceFile != "" {
					if _, err := fmt.Fprintf(w, "[x] %s:%d: schema validation error %s, %s : %s\n", sourceFile, errorLine, r.GroupVersionKind().String(), getResourceName(r), e.Error()); err != nil {
						return errors.Wrap(err, errWriteOutput)
					}
				} else {
					if _, err := fmt.Fprintf(w, "[x] schema validation error %s, %s : %s\n", r.GroupVersionKind().String(), getResourceName(r), e.Error()); err != nil {
						return errors.Wrap(err, errWriteOutput)
					}
				}
			}

			celValidator := cel.NewValidator(s, true, celconfig.PerCallLimit)

			celErrors, _ := celValidator.Validate(ctx, nil, s, r.Object, nil, celconfig.PerCallLimit)

			// Filter CEL required field errors too
			if patchCollector != nil && baseResourceName != "" {
				celErrors = filterCELRequiredErrors(celErrors, baseResourceName, patchCollector)
			}

			for _, e := range celErrors {
				rf++

				// Try to find the exact line using the error path
				errorLine := sourceLine
				if sourceFile != "" && e.Field != "" {
					exactLine := load.FindPathInYAML(sourceFile, sourceLine, e.Field)
					if exactLine > 0 {
						errorLine = exactLine
					}
				}

				if sourceFile != "" {
					if _, err := fmt.Fprintf(w, "[x] %s:%d: CEL validation error %s, %s : %s\n", sourceFile, errorLine, r.GroupVersionKind().String(), getResourceName(r), e.Error()); err != nil {
						return errors.Wrap(err, errWriteOutput)
					}
				} else {
					if _, err := fmt.Fprintf(w, "[x] CEL validation error %s, %s : %s\n", r.GroupVersionKind().String(), getResourceName(r), e.Error()); err != nil {
						return errors.Wrap(err, errWriteOutput)
					}
				}
			}

			if rf == 0 {
				if !skipSuccessLogs {
					if _, err := fmt.Fprintf(w, "[✓] %s, %s validated successfully\n", r.GroupVersionKind().String(), getResourceName(r)); err != nil {
						return errors.Wrap(err, errWriteOutput)
					}
				}
			} else {
				failure++
			}
		}
	}

	// Print missing schemas summary (always show this, even with --only-invalid)
	if len(missingGVKs) > 0 {
		if _, err := fmt.Fprintf(w, "\n[!] Missing schemas for %d resource types (add to --crd-sources):\n", len(missingGVKs)); err != nil {
			return errors.Wrap(err, errWriteOutput)
		}
		for gvk, count := range missingGVKs {
			if _, err := fmt.Fprintf(w, "    ❌ %s (%d resources)\n", gvk, count); err != nil {
				return errors.Wrap(err, errWriteOutput)
			}
		}
	}

	// Only print summary if we're showing success logs, or if there are failures/missing schemas
	if !skipSuccessLogs || failure > 0 || missingSchemas > 0 {
		if _, err := fmt.Fprintf(w, "Total %d resources: %d missing schemas, %d success cases, %d failure cases\n", len(resources), missingSchemas, len(resources)-failure-missingSchemas, failure); err != nil {
			return errors.Wrap(err, errWriteOutput)
		}
	}

	if failure > 0 {
		return errors.New("could not validate all resources")
	}

	if errorOnMissingSchemas && missingSchemas > 0 {
		return errors.New("could not validate all resources, schema(s) missing")
	}

	return nil
}

// filterCELRequiredErrors filters out CEL required field errors for patched fields.
func filterCELRequiredErrors(errors field.ErrorList, resourceName string, collector *PatchedFieldsCollector) field.ErrorList {
	if collector == nil {
		return errors
	}

	filtered := make(field.ErrorList, 0, len(errors))
	for _, err := range errors {
		// Check if this is a "required parameter" CEL error
		if IsCELRequiredError(err) {
			// Extract the field path from the error message
			fieldPath := ExtractRequiredFieldFromCEL(err)
			if fieldPath != "" && collector.IsFieldPatched(resourceName, fieldPath) {
				// Skip this error - the field will be patched in
				continue
			}
		}
		filtered = append(filtered, err)
	}
	return filtered
}

func getResourceName(r *unstructured.Unstructured) string {
	if r.GetName() != "" {
		return r.GetName()
	}

	// fallback to composition resource name
	return r.GetAnnotations()[xcrd.AnnotationKeyCompositionResourceName]
}

// applyDefaults applies default values from the CRD schema to the unstructured resource.
func applyDefaults(resource *unstructured.Unstructured, gvk runtimeschema.GroupVersionKind, crds []*extv1.CustomResourceDefinition) error {
	var matchingCRD *extv1.CustomResourceDefinition

	for _, crd := range crds {
		if crd.Spec.Group == gvk.Group && crd.Spec.Names.Kind == gvk.Kind {
			matchingCRD = crd
			break
		}
	}

	if matchingCRD == nil {
		// no CRD found for applying defaults, skip defaulting
		return nil
	}

	var schemaProps *extv1.JSONSchemaProps

	for _, v := range matchingCRD.Spec.Versions {
		if v.Name == gvk.Version {
			if v.Schema != nil && v.Schema.OpenAPIV3Schema != nil {
				schemaProps = v.Schema.OpenAPIV3Schema
			}

			break
		}
	}

	if schemaProps == nil {
		return fmt.Errorf("no schema found for version %s in CRD %s", gvk.Version, matchingCRD.Name)
	}

	var apiExtSchema ext.JSONSchemaProps

	err := extv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(schemaProps, &apiExtSchema, nil)
	if err != nil {
		return fmt.Errorf("failed to convert schema: %w", err)
	}

	structural, err := schema.NewStructural(&apiExtSchema)
	if err != nil {
		return fmt.Errorf("failed to create structural schema: %w", err)
	}

	obj := resource.UnstructuredContent()
	structuraldefaulting.Default(obj, structural)

	return nil
}
