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
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestSchemaNavigator_ValidatePath(t *testing.T) {
	// Create a test CRD with a known schema
	testCRD := &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "teststamps.test.example.com",
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "test.example.com",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:   "TestStamp",
				Plural: "teststamps",
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1alpha1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"parameters": {
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"region": {
													Type: "string",
												},
												"environment": {
													Type: "string",
												},
												"nodePool": {
													Type: "object",
													Properties: map[string]extv1.JSONSchemaProps{
														"minSize": {
															Type: "integer",
														},
														"maxSize": {
															Type: "integer",
														},
													},
												},
												"tags": {
													Type:                   "object",
													XPreserveUnknownFields: boolPtr(true),
												},
												"items": {
													Type: "array",
													Items: &extv1.JSONSchemaPropsOrArray{
														Schema: &extv1.JSONSchemaProps{
															Type: "object",
															Properties: map[string]extv1.JSONSchemaProps{
																"name": {Type: "string"},
															},
														},
													},
												},
											},
										},
									},
								},
								"status": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"vpcId": {
											Type: "string",
										},
									},
								},
								"metadata": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"name": {Type: "string"},
										"labels": {
											Type: "object",
											AdditionalProperties: &extv1.JSONSchemaPropsOrBool{
												Schema: &extv1.JSONSchemaProps{Type: "string"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{testCRD})

	testGVK := schema.GroupVersionKind{
		Group:   "test.example.com",
		Version: "v1alpha1",
		Kind:    "TestStamp",
	}

	tests := map[string]struct {
		path    string
		want    bool
		wantErr string
	}{
		"ValidSimplePath": {
			path: "spec.parameters.region",
			want: true,
		},
		"ValidNestedPath": {
			path: "spec.parameters.nodePool.minSize",
			want: true,
		},
		"ValidStatusPath": {
			path: "status.vpcId",
			want: true,
		},
		"ValidMetadataPath": {
			path: "metadata.name",
			want: true,
		},
		"ValidPreserveUnknownFields": {
			path: "spec.parameters.tags.anyKey",
			want: true,
		},
		"ValidArrayAccess": {
			path: "spec.parameters.items[0].name",
			want: true,
		},
		"ValidWildcardArrayAccess": {
			path: "spec.parameters.items[*].name",
			want: true,
		},
		"InvalidFieldNotFound": {
			path:    "spec.parameters.nonexistent",
			want:    false,
			wantErr: "field not found",
		},
		"InvalidNestedFieldNotFound": {
			path:    "spec.parameters.nodePool.invalid",
			want:    false,
			wantErr: "field not found",
		},
		"InvalidTypoInPath": {
			path:    "spec.paramters.region",
			want:    false,
			wantErr: "field not found",
		},
		"InvalidDeepPath": {
			path:    "spec.parameters.region.invalid",
			want:    false,
			wantErr: "has no properties",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := navigator.ValidatePath(testGVK, tc.path)

			if result.Valid != tc.want {
				t.Errorf("ValidatePath(%s) valid = %v, want %v", tc.path, result.Valid, tc.want)
			}

			if !tc.want && tc.wantErr != "" {
				if result.Reason == "" {
					t.Errorf("ValidatePath(%s) expected error containing %q, got no error", tc.path, tc.wantErr)
				}
			}
		})
	}
}

func TestCompositionParser_Parse(t *testing.T) {
	// Create a test composition
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "test.example.com/v1alpha1",
					"kind":       "TestStamp",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "resource-a",
									"base": map[string]interface{}{
										"apiVersion": "other.example.com/v1",
										"kind":       "OtherResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.forProvider.region",
										},
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.id",
											"toFieldPath":   "status.vpcId",
										},
										map[string]interface{}{
											"type":        "CombineFromComposite",
											"toFieldPath": "spec.forProvider.name",
											"combine": map[string]interface{}{
												"strategy": "string",
												"variables": []interface{}{
													map[string]interface{}{
														"fromFieldPath": "metadata.name",
													},
													map[string]interface{}{
														"fromFieldPath": "spec.parameters.environment",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	compositions := parser.GetCompositions()
	if len(compositions) != 1 {
		t.Fatalf("Expected 1 composition, got %d", len(compositions))
	}

	comp := compositions[0]

	// Check composite type ref
	expectedGVK := schema.GroupVersionKind{
		Group:   "test.example.com",
		Version: "v1alpha1",
		Kind:    "TestStamp",
	}
	if diff := cmp.Diff(expectedGVK, comp.CompositeTypeRef); diff != "" {
		t.Errorf("CompositeTypeRef mismatch (-want +got):\n%s", diff)
	}

	// Check patches extracted
	if len(comp.AllPatches) != 3 {
		t.Errorf("Expected 3 patches, got %d", len(comp.AllPatches))
	}

	// Check fromFieldPaths
	fromPaths := parser.GetAllFromFieldPaths()
	expectedFromPaths := []string{
		"spec.parameters.region",
		"status.id",
		"metadata.name",
		"spec.parameters.environment",
	}

	if len(fromPaths) != len(expectedFromPaths) {
		t.Errorf("Expected %d fromFieldPaths, got %d", len(expectedFromPaths), len(fromPaths))
	}
}

func TestPatchValidator_Validate(t *testing.T) {
	// Create test CRD
	testCRD := &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "teststamps.test.example.com",
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "test.example.com",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:   "TestStamp",
				Plural: "teststamps",
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1alpha1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"parameters": {
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"region": {Type: "string"},
												"environment": {Type: "string"},
												"unusedParam": {Type: "string"}, // This is unused
											},
										},
									},
								},
								"metadata": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"name": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create composition with valid and invalid patches
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "test.example.com/v1alpha1",
					"kind":       "TestStamp",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "resource-a",
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.forProvider.region",
										},
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.invalidField", // Invalid!
											"toFieldPath":   "spec.forProvider.other",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	config := PatchValidationConfig{
		ValidatePatchPaths: true,
		DetectUnusedParams: true,
		StrictMode:         false,
		SkipMissingSchemas: true,
	}

	validator := NewPatchValidator([]*extv1.CustomResourceDefinition{testCRD}, config)
	if err := validator.LoadCompositions([]*unstructured.Unstructured{composition}); err != nil {
		t.Fatalf("LoadCompositions() error = %v", err)
	}

	var buf bytes.Buffer
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Should have found the invalid patch
	if result.InvalidPatches == 0 {
		t.Error("Expected to find invalid patches, but found none")
	}

	// Should have found the unused parameter
	if result.UnusedParameters == 0 {
		t.Error("Expected to find unused parameters, but found none")
	}

	// Check that unusedParam is in the list
	foundUnused := false
	for _, param := range result.UnusedParams {
		if param.Path == "spec.parameters.unusedParam" {
			foundUnused = true
			break
		}
	}
	if !foundUnused {
		t.Error("Expected 'spec.parameters.unusedParam' to be in unused params")
	}
}

func TestExtractParameterPaths(t *testing.T) {
	schema := &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"parameters": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"region": {Type: "string"},
							"nodePool": {
								Type: "object",
								Properties: map[string]extv1.JSONSchemaProps{
									"minSize": {Type: "integer"},
									"maxSize": {Type: "integer"},
								},
							},
						},
					},
				},
			},
		},
	}

	paths := ExtractParameterPaths(schema, "", 5)

	// Check that expected paths are present
	expectedPaths := map[string]bool{
		"spec":                            true,
		"spec.parameters":                 true,
		"spec.parameters.region":          true,
		"spec.parameters.nodePool":        true,
		"spec.parameters.nodePool.minSize": true,
		"spec.parameters.nodePool.maxSize": true,
	}

	for _, path := range paths {
		delete(expectedPaths, path)
	}

	if len(expectedPaths) > 0 {
		t.Errorf("Missing expected paths: %v", expectedPaths)
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestSchemaNavigator_CompareObjectSchemas(t *testing.T) {
	// Source CRD (PlatformStampV2) - has osSku field
	sourceCRD := &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "platformstamps.cloud.example.com"},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "cloud.example.com",
			Names: extv1.CustomResourceDefinitionNames{Kind: "PlatformStamp", Plural: "platformstamps"},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1alpha1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"parameters": {
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"azure": {
													Type: "object",
													Properties: map[string]extv1.JSONSchemaProps{
														"nodePool": {
															Type: "object",
															Properties: map[string]extv1.JSONSchemaProps{
																"minSize": {Type: "integer"},
																"maxSize": {Type: "integer"},
																"osSku":   {Type: "string"}, // This field exists in source
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Target CRD (StampCommonV2) - MISSING osSku field
	targetCRD := &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "stampcommons.cloud.example.com"},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "cloud.example.com",
			Names: extv1.CustomResourceDefinitionNames{Kind: "StampCommon", Plural: "stampcommons"},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1alpha1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"parameters": {
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"azure": {
													Type: "object",
													Properties: map[string]extv1.JSONSchemaProps{
														"nodePool": {
															Type: "object",
															Properties: map[string]extv1.JSONSchemaProps{
																"minSize": {Type: "integer"},
																"maxSize": {Type: "integer"},
																// osSku is MISSING here!
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{sourceCRD, targetCRD})

	sourceGVK := schema.GroupVersionKind{Group: "cloud.example.com", Version: "v1alpha1", Kind: "PlatformStamp"}
	targetGVK := schema.GroupVersionKind{Group: "cloud.example.com", Version: "v1alpha1", Kind: "StampCommon"}

	// Compare the nodePool objects
	mismatches := navigator.CompareObjectSchemas(sourceGVK, targetGVK, "spec.parameters.azure.nodePool")

	if len(mismatches) == 0 {
		t.Fatal("Expected to find mismatches (osSku missing in target), got none")
	}

	// Check that osSku is in the mismatches
	foundOsSku := false
	for _, m := range mismatches {
		if m.Path == "osSku" {
			foundOsSku = true
			if m.SourceType != "string" {
				t.Errorf("Expected osSku type to be 'string', got '%s'", m.SourceType)
			}
		}
	}

	if !foundOsSku {
		t.Errorf("Expected to find 'osSku' in mismatches, got: %v", mismatches)
	}
}

func TestSchemaNavigator_CompareObjectSchemas_NoMismatch(t *testing.T) {
	// Both CRDs have the same fields
	crd := &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "teststamps.cloud.example.com"},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "cloud.example.com",
			Names: extv1.CustomResourceDefinitionNames{Kind: "TestStamp", Plural: "teststamps"},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1alpha1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"parameters": {
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"nodePool": {
													Type: "object",
													Properties: map[string]extv1.JSONSchemaProps{
														"minSize": {Type: "integer"},
														"maxSize": {Type: "integer"},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{crd})

	gvk := schema.GroupVersionKind{Group: "cloud.example.com", Version: "v1alpha1", Kind: "TestStamp"}

	// Compare same schema - should have no mismatches
	mismatches := navigator.CompareObjectSchemas(gvk, gvk, "spec.parameters.nodePool")

	if len(mismatches) > 0 {
		t.Errorf("Expected no mismatches when comparing same schema, got: %v", mismatches)
	}
}

func TestSchemaNavigator_CompareObjectSchemas_PreserveUnknownFields(t *testing.T) {
	// Source has fields, target has x-kubernetes-preserve-unknown-fields
	sourceCRD := &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "sources.cloud.example.com"},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "cloud.example.com",
			Names: extv1.CustomResourceDefinitionNames{Kind: "Source", Plural: "sources"},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1alpha1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"config": {
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"field1": {Type: "string"},
												"field2": {Type: "integer"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	targetCRD := &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "targets.cloud.example.com"},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "cloud.example.com",
			Names: extv1.CustomResourceDefinitionNames{Kind: "Target", Plural: "targets"},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1alpha1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"config": {
											Type:                   "object",
											XPreserveUnknownFields: boolPtr(true), // Accepts any fields
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{sourceCRD, targetCRD})

	sourceGVK := schema.GroupVersionKind{Group: "cloud.example.com", Version: "v1alpha1", Kind: "Source"}
	targetGVK := schema.GroupVersionKind{Group: "cloud.example.com", Version: "v1alpha1", Kind: "Target"}

	// Compare - should have no mismatches because target accepts unknown fields
	mismatches := navigator.CompareObjectSchemas(sourceGVK, targetGVK, "spec.config")

	if len(mismatches) > 0 {
		t.Errorf("Expected no mismatches when target has x-kubernetes-preserve-unknown-fields, got: %v", mismatches)
	}
}
