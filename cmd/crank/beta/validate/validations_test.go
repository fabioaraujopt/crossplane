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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// =============================================================================
// CRD Source Parsing Tests
// =============================================================================

func TestParseCRDSources(t *testing.T) {
	tests := map[string]struct {
		input   []string
		want    []CRDSource
		wantErr bool
	}{
		"GitHubSource": {
			input: []string{"github:crossplane/crossplane:main:cluster/crds"},
			want: []CRDSource{
				{Type: CRDSourceTypeGitHub, Location: "crossplane/crossplane", Branch: "main", Path: "cluster/crds"},
			},
		},
		"CatalogSource": {
			input: []string{"catalog:https://example.com/crds"},
			want: []CRDSource{
				{Type: CRDSourceTypeCatalog, Location: "https://example.com/crds"},
			},
		},
		"K8sSchemaSource": {
			input: []string{"k8s:v1.29.0"},
			want: []CRDSource{
				{Type: CRDSourceTypeK8sSchemas, Location: "v1.29.0"},
			},
		},
		"LocalSource": {
			input: []string{"local:/path/to/crds"},
			want: []CRDSource{
				{Type: CRDSourceTypeLocal, Location: "/path/to/crds"},
			},
		},
		"ClusterSource": {
			input: []string{"cluster"},
			want: []CRDSource{
				{Type: CRDSourceTypeCluster, Location: ""},
			},
		},
		"MultipleSources": {
			input: []string{
				"github:org/repo:main:path",
				"k8s:v1.29.0",
				"cluster",
			},
			want: []CRDSource{
				{Type: CRDSourceTypeGitHub, Location: "org/repo", Branch: "main", Path: "path"},
				{Type: CRDSourceTypeK8sSchemas, Location: "v1.29.0"},
				{Type: CRDSourceTypeCluster, Location: ""},
			},
		},
		"InvalidSource": {
			input:   []string{"invalid:source"},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseCRDSources(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseCRDSources() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if diff := cmp.Diff(tc.want, got); diff != "" {
					t.Errorf("ParseCRDSources() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// =============================================================================
// Schema Navigator Tests - Extended
// =============================================================================

func TestSchemaNavigator_ArrayIndexing(t *testing.T) {
	crd := createTestCRDWithArrays()
	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{crd})

	gvk := schema.GroupVersionKind{
		Group:   "test.example.com",
		Version: "v1",
		Kind:    "TestResource",
	}

	tests := map[string]struct {
		path      string
		wantValid bool
	}{
		"NumericArrayIndex":    {path: "spec.items[0].name", wantValid: true},
		"WildcardArrayIndex":   {path: "spec.items[*].name", wantValid: true},
		"NestedArrayIndex":     {path: "spec.items[0].values[1]", wantValid: true},
		"InvalidArrayIndex":    {path: "spec.items[x].name", wantValid: false},
		"ArrayIntoNonArray":    {path: "spec.name[0]", wantValid: false},
		"PathAfterArrayItem":   {path: "spec.items[0].nested.field", wantValid: true},
		"MissingFieldInArray":  {path: "spec.items[0].nonexistent", wantValid: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := navigator.ValidatePath(gvk, tc.path)
			if result.Valid != tc.wantValid {
				t.Errorf("ValidatePath(%s) = %v, want %v (reason: %s)",
					tc.path, result.Valid, tc.wantValid, result.Reason)
			}
		})
	}
}

func TestSchemaNavigator_PreserveUnknownFields(t *testing.T) {
	crd := createTestCRDWithPreserveUnknown()
	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{crd})

	gvk := schema.GroupVersionKind{
		Group:   "test.example.com",
		Version: "v1",
		Kind:    "TestResource",
	}

	tests := map[string]struct {
		path      string
		wantValid bool
	}{
		"KnownFieldBeforePreserve": {path: "spec.forProvider.manifest", wantValid: true},
		"AnyFieldUnderPreserve":    {path: "spec.forProvider.manifest.anything", wantValid: true},
		"DeepUnknownPath":          {path: "spec.forProvider.manifest.deep.nested.path", wantValid: true},
		"KnownFieldNotPreserve":    {path: "spec.forProvider.region", wantValid: true},
		"UnknownFieldNotPreserve":  {path: "spec.forProvider.unknown", wantValid: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := navigator.ValidatePath(gvk, tc.path)
			if result.Valid != tc.wantValid {
				t.Errorf("ValidatePath(%s) = %v, want %v (reason: %s)",
					tc.path, result.Valid, tc.wantValid, result.Reason)
			}
		})
	}
}

func TestSchemaNavigator_AdditionalProperties(t *testing.T) {
	crd := createTestCRDWithAdditionalProps()
	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{crd})

	gvk := schema.GroupVersionKind{
		Group:   "test.example.com",
		Version: "v1",
		Kind:    "TestResource",
	}

	tests := map[string]struct {
		path      string
		wantValid bool
	}{
		"AdditionalPropsAnyKey": {path: "metadata.labels.anyKey", wantValid: true},
		// Note: The schema navigator allows deep paths under additionalProperties
		// Annotations are string maps, so metadata.annotations.anykey returns a string
		// You cannot navigate into a string value, so metadata.annotations.deep.key is invalid
		"AdditionalPropsDeepKey": {path: "metadata.annotations.deep.key", wantValid: false},
		// Valid annotation access with bracket notation
		"AdditionalPropsBracket": {path: "metadata.annotations[\"my-key\"]", wantValid: true},
		"KnownField":             {path: "metadata.name", wantValid: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := navigator.ValidatePath(gvk, tc.path)
			if result.Valid != tc.wantValid {
				t.Errorf("ValidatePath(%s) = %v, want %v (reason: %s)",
					tc.path, result.Valid, tc.wantValid, result.Reason)
			}
		})
	}
}

// =============================================================================
// ObjectMeta Validation Tests
// =============================================================================

func TestSchemaNavigator_ObjectMetaValidation(t *testing.T) {
	// Create a simple CRD to test against (reuse array CRD which has valid schema)
	crd := createTestCRDWithArrays()
	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{crd})

	gvk := schema.GroupVersionKind{
		Group:   "test.example.com",
		Version: "v1",
		Kind:    "TestResource",
	}

	tests := map[string]struct {
		path      string
		wantValid bool
	}{
		// Valid ObjectMeta fields
		"ValidMetadataName":               {path: "metadata.name", wantValid: true},
		"ValidMetadataNamespace":          {path: "metadata.namespace", wantValid: true},
		"ValidMetadataLabels":             {path: "metadata.labels", wantValid: true},
		"ValidMetadataAnnotations":        {path: "metadata.annotations", wantValid: true},
		"ValidMetadataUID":                {path: "metadata.uid", wantValid: true},
		"ValidMetadataGeneration":         {path: "metadata.generation", wantValid: true},
		"ValidMetadataResourceVersion":    {path: "metadata.resourceVersion", wantValid: true},
		"ValidMetadataCreationTimestamp":  {path: "metadata.creationTimestamp", wantValid: true},
		"ValidMetadataDeletionTimestamp":  {path: "metadata.deletionTimestamp", wantValid: true},
		"ValidMetadataFinalizers":         {path: "metadata.finalizers", wantValid: true},
		"ValidMetadataOwnerReferences":    {path: "metadata.ownerReferences", wantValid: true},
		"ValidMetadataManagedFields":      {path: "metadata.managedFields", wantValid: true},
		"ValidMetadataGenerateName":       {path: "metadata.generateName", wantValid: true},
		"ValidMetadataLabelsBracket":      {path: "metadata.labels[\"app\"]", wantValid: true},
		"ValidMetadataAnnotationsBracket": {path: "metadata.annotations[\"key\"]", wantValid: true},
		"ValidMetadataFinalizer0":         {path: "metadata.finalizers[0]", wantValid: true},
		"ValidOwnerRefField":              {path: "metadata.ownerReferences[0].name", wantValid: true},

		// Invalid ObjectMeta fields (typos or non-existent fields)
		"InvalidMetadataPica":      {path: "metadata.pica", wantValid: false},
		"InvalidMetadataFoo":       {path: "metadata.foo", wantValid: false},
		"InvalidMetadataLabel":     {path: "metadata.label", wantValid: false}, // Should be "labels"
		"InvalidMetadataAnnotation": {path: "metadata.annotation", wantValid: false}, // Should be "annotations"

		// apiVersion and kind are valid top-level fields but can't have sub-paths
		"ValidApiVersion":        {path: "apiVersion", wantValid: true},
		"ValidKind":              {path: "kind", wantValid: true},
		"InvalidApiVersionDotFoo": {path: "apiVersion.foo", wantValid: false},
		"InvalidKindDotBar":       {path: "kind.bar", wantValid: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := navigator.ValidatePath(gvk, tc.path)
			if result.Valid != tc.wantValid {
				t.Errorf("ValidatePath(%s) = %v, want %v (reason: %s)",
					tc.path, result.Valid, tc.wantValid, result.Reason)
			}
		})
	}
}

// =============================================================================
// Duplicate toFieldPath Detection Tests
// =============================================================================

func TestDuplicateToFieldPathDetection(t *testing.T) {
	// Create a composition with duplicate toFieldPath
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
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.example.com/v1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "spec.field1",
											"toFieldPath":   "spec.forProvider.name", // First write
										},
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "spec.field2",
											"toFieldPath":   "spec.forProvider.name", // Duplicate!
										},
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "spec.field3",
											"toFieldPath":   "spec.forProvider.region", // Different field - OK
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

	validator := NewCompositionValidator([]*unstructured.Unstructured{composition}, nil)

	// Access the internal method for testing
	warnings := validator.detectDuplicateToFieldPaths(composition)

	// Should have 1 warning for the duplicate toFieldPath
	if len(warnings) != 1 {
		t.Errorf("Expected 1 warning for duplicate toFieldPath, got %d", len(warnings))
		for _, w := range warnings {
			t.Logf("Warning: %s", w.Message)
		}
		return
	}

	// Verify the warning message mentions the duplicate field
	if !strings.Contains(warnings[0].Message, "spec.forProvider.name") {
		t.Errorf("Warning message should mention the duplicate field path, got: %s", warnings[0].Message)
	}
	if !strings.Contains(warnings[0].Message, "multiple patches") {
		t.Errorf("Warning message should mention multiple patches, got: %s", warnings[0].Message)
	}
}

// =============================================================================
// Composition Parser Tests - PatchSet Resolution
// =============================================================================

func TestCompositionParser_PatchSetResolution(t *testing.T) {
	composition := createCompositionWithPatchSets()

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

	// Check that resources were parsed
	if len(comp.Resources) == 0 {
		t.Error("Expected at least 1 resource")
	}

	// Check that AllPatches includes the resolved patches from PatchSets
	// The resource references "common-patches" PatchSet which has 2 patches, plus 1 direct patch
	// Total should be at least 3 patches in AllPatches
	if len(comp.AllPatches) < 3 {
		t.Errorf("Expected at least 3 patches in AllPatches (including resolved PatchSet patches), got %d", len(comp.AllPatches))
	}
}

func TestCompositionParser_UnusedPatchSets(t *testing.T) {
	composition := createCompositionWithUnusedPatchSet()

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// TODO: Implement unused PatchSet detection
	// For now, just verify parsing works
	compositions := parser.GetCompositions()
	if len(compositions) != 1 {
		t.Fatalf("Expected 1 composition, got %d", len(compositions))
	}
}

// =============================================================================
// Transform Validation Tests
// =============================================================================

func TestTransformValidation(t *testing.T) {
	// Create CRD with function input schema for transforms
	crd := createFunctionInputCRD()
	navigator := NewSchemaNavigator([]*extv1.CustomResourceDefinition{crd})

	gvk := schema.GroupVersionKind{
		Group:   "pt.fn.crossplane.io",
		Version: "v1beta1",
		Kind:    "Resources",
	}

	// Test that the CRD was registered
	if !navigator.HasSchema(gvk) {
		t.Fatal("Function input CRD not found in navigator")
	}
}

// =============================================================================
// Unused Parameter Detection Tests
// =============================================================================

func TestUnusedParameterDetection(t *testing.T) {
	// Create XRD with parameters
	xrd := createTestXRD()

	// Create composition that uses only some parameters
	composition := createCompositionWithPartialParams()

	config := PatchValidationConfig{
		ValidatePatchPaths: true,
		DetectUnusedParams: true,
		StrictMode:         false,
		SkipMissingSchemas: true,
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{xrd})
	validator := NewPatchValidator(crds, config)

	if err := validator.LoadCompositions([]*unstructured.Unstructured{composition}); err != nil {
		t.Fatalf("LoadCompositions() error = %v", err)
	}

	var buf bytes.Buffer
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Should detect unused parameters
	if result.UnusedParameters == 0 {
		t.Error("Expected to find unused parameters")
	}

	// Check specific unused param
	foundUnused := false
	for _, param := range result.UnusedParams {
		if param.Path == "spec.parameters.unusedField" {
			foundUnused = true
			break
		}
	}
	if !foundUnused {
		t.Error("Expected 'spec.parameters.unusedField' to be detected as unused")
	}
}

// =============================================================================
// GVK Discovery Tests
// =============================================================================

func TestDiscoverRequiredGVKs(t *testing.T) {
	composition := createCompositionWithMultipleResources()

	gvks := discoverRequiredGVKs([]*unstructured.Unstructured{composition}, nil)

	expectedGVKs := []string{
		"apiextensions.crossplane.io/v1, Kind=Composition", // The composition itself
		"s3.aws.upbound.io/v1beta1, Kind=Bucket",
		"iam.aws.upbound.io/v1beta1, Kind=Role",
		"pt.fn.crossplane.io/v1beta1, Kind=Resources", // Function input
	}

	for _, expected := range expectedGVKs {
		if !gvks[expected] {
			t.Errorf("Expected GVK %s not found", expected)
		}
	}
}

func TestDiscoverNestedGVKs(t *testing.T) {
	composition := createCompositionWithNestedManifest()

	gvks := discoverRequiredGVKs([]*unstructured.Unstructured{composition}, nil)

	// Should discover the nested manifest GVK
	nestedGVK := "karpenter.sh/v1, Kind=NodePool"
	if !gvks[nestedGVK] {
		t.Errorf("Nested GVK %s not discovered", nestedGVK)
	}
}

// =============================================================================
// Base Resource Required Field Filtering Tests
// =============================================================================

func TestPatchedFieldsCollector(t *testing.T) {
	// Create a parsed composition with patches
	comp := &ParsedComposition{
		Name: "test-composition",
		Resources: []ComposedResource{
			{
				Name: "test-resource",
				Patches: []Patch{
					{ToFieldPath: "spec.forProvider.region"},
					{ToFieldPath: "spec.forProvider.name"},
					{ToFieldPath: "metadata.labels.app"},
				},
			},
		},
	}

	collector := NewPatchedFieldsCollector()
	collector.CollectFromComposition(comp)

	// Check that fields are tracked
	if !collector.IsFieldPatched("test-resource", "spec.forProvider.region") {
		t.Error("Expected spec.forProvider.region to be tracked as patched")
	}

	if !collector.IsFieldPatched("test-resource", "spec.forProvider.name") {
		t.Error("Expected spec.forProvider.name to be tracked as patched")
	}

	// Check that non-patched fields return false
	if collector.IsFieldPatched("test-resource", "spec.forProvider.other") {
		t.Error("Expected spec.forProvider.other to NOT be tracked as patched")
	}

	// Check different resource name
	if collector.IsFieldPatched("other-resource", "spec.forProvider.region") {
		t.Error("Expected field on different resource to NOT be tracked")
	}
}

func TestPatchedFieldsCollector_PatchSets(t *testing.T) {
	// Create a composition where patches come from both direct patches and AllPatches
	// (which would include resolved PatchSet patches)
	comp := &ParsedComposition{
		Name: "test-composition",
		Resources: []ComposedResource{
			{
				Name: "azure-resource",
				Patches: []Patch{
					{ToFieldPath: "spec.forProvider.name"},
				},
			},
		},
		// AllPatches includes resolved PatchSet patches
		AllPatches: []PatchInfo{
			{
				ResourceName: "azure-resource",
				Patch:        Patch{ToFieldPath: "spec.forProvider.location"},
			},
			{
				ResourceName: "azure-resource",
				Patch:        Patch{ToFieldPath: "spec.forProvider.resourceGroup"},
			},
			{
				ResourceName: "azure-resource",
				Patch:        Patch{ToFieldPath: "spec.forProvider.name"},
			},
		},
	}

	collector := NewPatchedFieldsCollector()
	collector.CollectFromComposition(comp)

	// All should be tracked
	for _, field := range []string{
		"spec.forProvider.location",
		"spec.forProvider.resourceGroup",
		"spec.forProvider.name",
	} {
		if !collector.IsFieldPatched("azure-resource", field) {
			t.Errorf("Expected %s to be tracked as patched", field)
		}
	}
}

// =============================================================================
// Helper Functions - Create Test Data
// =============================================================================

func createTestCRDWithArrays() *extv1.CustomResourceDefinition {
	return &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testresources.test.example.com",
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "test.example.com",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:   "TestResource",
				Plural: "testresources",
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"name": {Type: "string"},
										"items": {
											Type: "array",
											Items: &extv1.JSONSchemaPropsOrArray{
												Schema: &extv1.JSONSchemaProps{
													Type: "object",
													Properties: map[string]extv1.JSONSchemaProps{
														"name": {Type: "string"},
														"values": {
															Type: "array",
															Items: &extv1.JSONSchemaPropsOrArray{
																Schema: &extv1.JSONSchemaProps{Type: "string"},
															},
														},
														"nested": {
															Type: "object",
															Properties: map[string]extv1.JSONSchemaProps{
																"field": {Type: "string"},
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
}

func createTestCRDWithPreserveUnknown() *extv1.CustomResourceDefinition {
	preserveTrue := true
	return &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testresources.test.example.com",
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "test.example.com",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:   "TestResource",
				Plural: "testresources",
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]extv1.JSONSchemaProps{
										"forProvider": {
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"region": {Type: "string"},
												"manifest": {
													Type:                   "object",
													XPreserveUnknownFields: &preserveTrue,
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
}

func createTestCRDWithAdditionalProps() *extv1.CustomResourceDefinition {
	return &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testresources.test.example.com",
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "test.example.com",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:   "TestResource",
				Plural: "testresources",
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
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
										"annotations": {
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
}

func createCompositionWithPatchSets() *unstructured.Unstructured {
	return &unstructured.Unstructured{
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
							"patchSets": []interface{}{
								map[string]interface{}{
									"name": "common-patches",
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.forProvider.region",
										},
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.environment",
											"toFieldPath":   "spec.forProvider.tags.env",
										},
									},
								},
								map[string]interface{}{
									"name": "unused-patchset",
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.unused",
											"toFieldPath":   "spec.forProvider.unused",
										},
									},
								},
							},
							"resources": []interface{}{
								map[string]interface{}{
									"name": "resource-with-patchset",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":         "PatchSet",
											"patchSetName": "common-patches",
										},
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.name",
											"toFieldPath":   "spec.forProvider.bucket",
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
}

func createCompositionWithUnusedPatchSet() *unstructured.Unstructured {
	return createCompositionWithPatchSets() // Same structure, has unused-patchset
}

func createFunctionInputCRD() *extv1.CustomResourceDefinition {
	return &extv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "resources.pt.fn.crossplane.io",
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "pt.fn.crossplane.io",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:   "Resources",
				Plural: "resources",
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   "v1beta1",
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"resources": {
									Type: "array",
									Items: &extv1.JSONSchemaPropsOrArray{
										Schema: &extv1.JSONSchemaProps{
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"name": {Type: "string"},
												"patches": {
													Type: "array",
													Items: &extv1.JSONSchemaPropsOrArray{
														Schema: &extv1.JSONSchemaProps{
															Type: "object",
															Properties: map[string]extv1.JSONSchemaProps{
																"type": {
																	Type: "string",
																	Enum: []extv1.JSON{
																		{Raw: []byte(`"FromCompositeFieldPath"`)},
																		{Raw: []byte(`"ToCompositeFieldPath"`)},
																		{Raw: []byte(`"CombineFromComposite"`)},
																		{Raw: []byte(`"PatchSet"`)},
																	},
																},
																"fromFieldPath": {Type: "string"},
																"toFieldPath":   {Type: "string"},
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
}

func createTestXRD() *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "teststamps.test.example.com",
			},
			"spec": map[string]interface{}{
				"group": "test.example.com",
				"names": map[string]interface{}{
					"kind":   "TestStamp",
					"plural": "teststamps",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"referenceable": true,
						"served":        true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"parameters": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"region":      map[string]interface{}{"type": "string"},
													"environment": map[string]interface{}{"type": "string"},
													"unusedField": map[string]interface{}{"type": "string"},
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
}

func createCompositionWithPartialParams() *unstructured.Unstructured {
	return &unstructured.Unstructured{
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
									"name": "bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.forProvider.region",
										},
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.environment",
											"toFieldPath":   "spec.forProvider.tags.env",
										},
										// Note: unusedField is NOT used!
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createCompositionWithMultipleResources() *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "multi-resource-composition",
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
									"name": "bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
								},
								map[string]interface{}{
									"name": "role",
									"base": map[string]interface{}{
										"apiVersion": "iam.aws.upbound.io/v1beta1",
										"kind":       "Role",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func createCompositionWithNestedManifest() *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "nested-manifest-composition",
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
									"name": "k8s-object",
									"base": map[string]interface{}{
										"apiVersion": "kubernetes.crossplane.io/v1alpha2",
										"kind":       "Object",
										"spec": map[string]interface{}{
											"forProvider": map[string]interface{}{
												"manifest": map[string]interface{}{
													"apiVersion": "karpenter.sh/v1",
													"kind":       "NodePool",
													"spec": map[string]interface{}{
														"template": map[string]interface{}{
															"spec": map[string]interface{}{
																"requirements": []interface{}{},
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
}

// =============================================================================
// CompositeTypeRef Validation Tests
// =============================================================================

func TestValidateCompositeTypeRefs(t *testing.T) {
	// Create XRDs
	xrds := []*unstructured.Unstructured{
		createXRDWithKind("TestStampV1"),
		createXRDWithKind("TestStampV2"),
	}

	tests := map[string]struct {
		compositionKind string
		wantError       bool
	}{
		"ValidRef": {
			compositionKind: "TestStampV1",
			wantError:       false,
		},
		"ValidRefV2": {
			compositionKind: "TestStampV2",
			wantError:       false,
		},
		"InvalidRef": {
			compositionKind: "TestStampV3", // Doesn't exist!
			wantError:       true,
		},
		"TypoInRef": {
			compositionKind: "TeststampV1", // Case matters
			wantError:       true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			comp := createCompositionWithTypeRef(tc.compositionKind)
			errors := ValidateCompositeTypeRefs([]*unstructured.Unstructured{comp}, xrds)

			if tc.wantError && len(errors) == 0 {
				t.Error("Expected error but got none")
			}
			if !tc.wantError && len(errors) > 0 {
				t.Errorf("Expected no error but got: %v", errors)
			}
		})
	}
}

// =============================================================================
// PatchSet Reference Validation Tests
// =============================================================================

func TestValidatePatchSetReferences(t *testing.T) {
	// Create XRD so compositeTypeRef validation passes
	xrds := []*unstructured.Unstructured{createXRDWithKind("TestStamp")}

	tests := map[string]struct {
		composition *unstructured.Unstructured
		wantErrors  int
		wantWarns   int
	}{
		"ValidPatchSetRef": {
			composition: createCompositionWithPatchSetRef("common-patches", true),
			wantErrors:  0,
			wantWarns:   0,
		},
		"InvalidPatchSetRef": {
			composition: createCompositionWithPatchSetRef("nonexistent", true),
			wantErrors:  1,
			wantWarns:   1, // common-patches is unused since we reference "nonexistent"
		},
		"UnusedPatchSet": {
			composition: createCompositionWithUnusedPatchSetForValidation(),
			wantErrors:  0,
			wantWarns:   1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			validator := NewCompositionValidator(
				[]*unstructured.Unstructured{tc.composition},
				xrds,
			)

			var buf bytes.Buffer
			result, err := validator.Validate(&buf)
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}

			if len(result.Errors) != tc.wantErrors {
				t.Errorf("Expected %d errors, got %d: %v", tc.wantErrors, len(result.Errors), result.Errors)
			}
			if len(result.Warnings) != tc.wantWarns {
				t.Errorf("Expected %d warnings, got %d: %v", tc.wantWarns, len(result.Warnings), result.Warnings)
			}
		})
	}
}

// =============================================================================
// Helper Functions - Create Test Data for Composition Validation
// =============================================================================

func createXRDWithKind(kind string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": strings.ToLower(kind) + "s.test.example.com",
			},
			"spec": map[string]interface{}{
				"group": "test.example.com",
				"names": map[string]interface{}{
					"kind":   kind,
					"plural": strings.ToLower(kind) + "s",
				},
			},
		},
	}
}

func createCompositionWithTypeRef(kind string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "test.example.com/v1alpha1",
					"kind":       kind,
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
							"resources":  []interface{}{},
						},
					},
				},
			},
		},
	}
}

func createCompositionWithPatchSetRef(patchSetName string, definePatchSet bool) *unstructured.Unstructured {
	patchSets := []interface{}{}
	if definePatchSet {
		patchSets = append(patchSets, map[string]interface{}{
			"name": "common-patches",
			"patches": []interface{}{
				map[string]interface{}{
					"fromFieldPath": "spec.parameters.region",
					"toFieldPath":   "spec.forProvider.region",
				},
			},
		})
	}

	return &unstructured.Unstructured{
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
							"patchSets":  patchSets,
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":         "PatchSet",
											"patchSetName": patchSetName,
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
}

func createCompositionWithUnusedPatchSetForValidation() *unstructured.Unstructured {
	return &unstructured.Unstructured{
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
							"patchSets": []interface{}{
								map[string]interface{}{
									"name": "unused-patchset",
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.unused",
											"toFieldPath":   "spec.forProvider.unused",
										},
									},
								},
							},
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
									"patches": []interface{}{
										// No PatchSet reference - so "unused-patchset" is unused!
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.forProvider.region",
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
}

// ConvertXRDsToCRDs converts XRD objects to CRD format for testing
func ConvertXRDsToCRDs(xrds []*unstructured.Unstructured) []*extv1.CustomResourceDefinition {
	var crds []*extv1.CustomResourceDefinition

	for _, xrd := range xrds {
		group, _, _ := unstructured.NestedString(xrd.Object, "spec", "group")
		kind, _, _ := unstructured.NestedString(xrd.Object, "spec", "names", "kind")
		plural, _, _ := unstructured.NestedString(xrd.Object, "spec", "names", "plural")

		versions, _, _ := unstructured.NestedSlice(xrd.Object, "spec", "versions")
		var crdVersions []extv1.CustomResourceDefinitionVersion

		for _, v := range versions {
			vMap, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			versionName, _ := vMap["name"].(string)
			schema, _, _ := unstructured.NestedMap(vMap, "schema", "openAPIV3Schema")

			// Convert schema to JSONSchemaProps (simplified)
			crdVersion := extv1.CustomResourceDefinitionVersion{
				Name:   versionName,
				Served: true,
				Schema: &extv1.CustomResourceValidation{
					OpenAPIV3Schema: convertToJSONSchemaProps(schema),
				},
			}
			crdVersions = append(crdVersions, crdVersion)
		}

		crd := &extv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: plural + "." + group,
			},
			Spec: extv1.CustomResourceDefinitionSpec{
				Group: group,
				Names: extv1.CustomResourceDefinitionNames{
					Kind:   kind,
					Plural: plural,
				},
				Versions: crdVersions,
			},
		}
		crds = append(crds, crd)
	}

	return crds
}

func convertToJSONSchemaProps(schema map[string]interface{}) *extv1.JSONSchemaProps {
	if schema == nil {
		return nil
	}

	props := &extv1.JSONSchemaProps{}

	if t, ok := schema["type"].(string); ok {
		props.Type = t
	}

	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		props.Properties = make(map[string]extv1.JSONSchemaProps)
		for k, v := range properties {
			if vMap, ok := v.(map[string]interface{}); ok {
				converted := convertToJSONSchemaProps(vMap)
				if converted != nil {
					props.Properties[k] = *converted
				}
			}
		}
	}

	return props
}

// =============================================================================
// Status Chain Validation Tests
// =============================================================================

func TestStatusChainValidator_ValidChain(t *testing.T) {
	// Create a valid status propagation chain:
	// ChildXR writes to status.vpcId → ParentXR reads status.vpcId from ChildXR

	// Child XRD
	childXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xchildresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "ChildResource",
					"plural": "childresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"vpcId": map[string]interface{}{
												"type": "string",
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

	// Child Composition (writes to status.vpcId)
	childComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "child-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "ChildResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "vpc",
									"base": map[string]interface{}{
										"apiVersion": "ec2.aws.upbound.io/v1beta1",
										"kind":       "VPC",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.id",
											"toFieldPath":   "status.vpcId",
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

	// Parent XRD
	parentXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xparentresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "ParentResource",
					"plural": "parentresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"childVpcId": map[string]interface{}{
												"type": "string",
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

	// Parent Composition (reads status.vpcId from ChildResource)
	parentComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "parent-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "ParentResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "child",
									"base": map[string]interface{}{
										"apiVersion": "example.com/v1alpha1",
										"kind":       "ChildResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "status.vpcId",
											"toFieldPath":   "status.childVpcId",
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

	// Parse compositions
	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{childComposition, parentComposition, childXRD, parentXRD})
	if err != nil {
		t.Fatalf("Failed to parse compositions: %v", err)
	}

	// Create CRDs from XRDs
	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{childXRD, parentXRD})

	// Validate
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have NO errors - this is a valid chain
	errorCount := 0
	for _, issue := range issues {
		if issue.Severity == "error" {
			t.Errorf("Unexpected error: %s", issue.Message)
			errorCount++
		}
	}

	if errorCount > 0 {
		t.Fatalf("Expected no errors, got %d", errorCount)
	}
}

func TestStatusChainValidator_BrokenChain(t *testing.T) {
	// Parent reads status.vpcId from Child, but Child NEVER writes to it

	// Child XRD (defines status.vpcId)
	childXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xchildresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "ChildResource",
					"plural": "childresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"vpcId": map[string]interface{}{
												"type": "string",
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

	// Child Composition (does NOT write to status.vpcId - THIS IS THE BUG)
	childComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "child-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "ChildResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name":    "vpc",
									"base":    map[string]interface{}{
										"apiVersion": "ec2.aws.upbound.io/v1beta1",
										"kind":       "VPC",
									},
									"patches": []interface{}{
										// NO STATUS WRITE!
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Parent XRD (defines status.childVpcId so it can receive the value from child)
	parentXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xparentresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "ParentResource",
					"plural": "parentresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"childVpcId": map[string]interface{}{
												"type": "string",
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

	// Parent Composition (tries to read status.vpcId from Child)
	parentComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "parent-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "ParentResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "child",
									"base": map[string]interface{}{
										"apiVersion": "example.com/v1alpha1",
										"kind":       "ChildResource",
									},
									"patches": []interface{}{
										// ToCompositeFieldPath reads from child's status and writes to parent's status
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.vpcId",       // Reading from child's status
											"toFieldPath":   "status.childVpcId",  // Writing to parent's status
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

	// Parse compositions
	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{childComposition, parentComposition, childXRD, parentXRD})
	if err != nil {
		t.Fatalf("Failed to parse compositions: %v", err)
	}

	// Create CRDs from XRDs
	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{childXRD, parentXRD})

	// Validate
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have at least 1 ERROR
	errorCount := 0
	for _, issue := range issues {
		if issue.Severity == "error" {
			errorCount++
			// Verify the error message mentions the broken chain
			if !strings.Contains(issue.Message, "never writes to this status field") {
				t.Errorf("Error message should mention broken chain, got: %s", issue.Message)
			}
		}
	}

	if errorCount == 0 {
		t.Fatal("Expected at least 1 error for broken status chain, got none")
	}
}

func TestStatusChainValidator_MissingXRDField(t *testing.T) {
	// Composition writes to status.vpcId, but XRD doesn't define it

	// XRD WITHOUT status.vpcId field
	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xmyresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "MyResource",
					"plural": "myresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											// vpcId is NOT defined here
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

	// Composition that writes to undefined status field
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "my-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "MyResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "vpc",
									"base": map[string]interface{}{
										"apiVersion": "ec2.aws.upbound.io/v1beta1",
										"kind":       "VPC",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.id",
											"toFieldPath":   "status.vpcId", // vpcId not in XRD!
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

	// Parse
	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	// Create CRDs
	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{xrd})

	// Validate
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have at least 1 ERROR about missing XRD field
	errorCount := 0
	for _, issue := range issues {
		if issue.Severity == "error" {
			errorCount++
			if !strings.Contains(issue.Message, "doesn't define this field") {
				t.Errorf("Error should mention missing field definition, got: %s", issue.Message)
			}
		}
	}

	if errorCount == 0 {
		t.Fatal("Expected at least 1 error for missing XRD field, got none")
	}
}

func TestStatusChainValidator_InternalStatusUsage(t *testing.T) {
	// Status field used internally (written by one resource, read by another in same composition)
	// Should NOT be flagged as unused

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xmyresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "MyResource",
					"plural": "myresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"roleArn": map[string]interface{}{
												"type": "string",
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

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "my-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "MyResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "iam-role",
									"base": map[string]interface{}{
										"apiVersion": "iam.aws.upbound.io/v1beta1",
										"kind":       "Role",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.arn",
											"toFieldPath":   "status.roleArn", // Writes to status
										},
									},
								},
								map[string]interface{}{
									"name": "helm-release",
									"base": map[string]interface{}{
										"apiVersion": "helm.crossplane.io/v1beta1",
										"kind":       "Release",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "status.roleArn", // Reads from status (internal usage!)
											"toFieldPath":   "spec.forProvider.values.roleArn",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{xrd})
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have NO warnings about unused status.roleArn
	for _, issue := range issues {
		if strings.Contains(issue.Message, "status.roleArn") && strings.Contains(issue.Message, "never read") {
			t.Errorf("False positive: status.roleArn is used internally but flagged as unused: %s", issue.Message)
		}
	}
}

func TestStatusChainValidator_ProviderSpecificFields(t *testing.T) {
	// AWS composition uses status.roleArn, Azure doesn't
	// Should NOT warn because it's provider-specific (not unused in ALL compositions)

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xmulticloudresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "MultiCloudResource",
					"plural": "multicloudresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"roleArn": map[string]interface{}{
												"type": "string",
											},
											"identityId": map[string]interface{}{
												"type": "string",
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

	// AWS composition - writes status.roleArn
	awsComp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "multicloud-aws",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "MultiCloudResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "role",
									"base": map[string]interface{}{
										"apiVersion": "iam.aws.upbound.io/v1beta1",
										"kind":       "Role",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.arn",
											"toFieldPath":   "status.roleArn", // AWS-specific
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

	// Azure composition - writes status.identityId (different field)
	azureComp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "multicloud-azure",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "MultiCloudResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "identity",
									"base": map[string]interface{}{
										"apiVersion": "managedidentity.azure.upbound.io/v1beta1",
										"kind":       "UserAssignedIdentity",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.clientId",
											"toFieldPath":   "status.identityId", // Azure-specific
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
	err := parser.Parse([]*unstructured.Unstructured{awsComp, azureComp, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{xrd})
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should NOT warn about provider-specific fields
	for _, issue := range issues {
		if issue.Severity == "warning" {
			if strings.Contains(issue.Message, "status.roleArn") || strings.Contains(issue.Message, "status.identityId") {
				t.Errorf("False positive for provider-specific field: %s", issue.Message)
			}
		}
	}
}

func TestStatusChainValidator_CombineFromCompositeStatusRead(t *testing.T) {
	// CombineFromComposite reads from status via combine.variables[].fromFieldPath
	// Should be detected as internal status usage

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xmyresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "MyResource",
					"plural": "myresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"interruptionQueueArn": map[string]interface{}{
												"type": "string",
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

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "my-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "MyResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "sqs-queue",
									"base": map[string]interface{}{
										"apiVersion": "sqs.aws.upbound.io/v1beta1",
										"kind":       "Queue",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.arn",
											"toFieldPath":   "status.interruptionQueueArn", // Writes to status
										},
									},
								},
								map[string]interface{}{
									"name": "iam-policy",
									"base": map[string]interface{}{
										"apiVersion": "iam.aws.upbound.io/v1beta1",
										"kind":       "Policy",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":        "CombineFromComposite",
											"toFieldPath": "spec.forProvider.policy",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{
														"fromFieldPath": "status.interruptionQueueArn", // Reads from status!
													},
													map[string]interface{}{
														"fromFieldPath": "spec.parameters.region",
													},
												},
												"strategy": "string",
												"string": map[string]interface{}{
													"fmt": "policy-json-here",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{xrd})
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have NO warnings about unused status.interruptionQueueArn
	for _, issue := range issues {
		if strings.Contains(issue.Message, "status.interruptionQueueArn") && strings.Contains(issue.Message, "never read") {
			t.Errorf("False positive: status.interruptionQueueArn is used by CombineFromComposite but flagged as unused: %s", issue.Message)
		}
	}
}

func TestStatusChainValidator_DefaultPatchTypeStatusRead(t *testing.T) {
	// Patches without explicit type default to FromCompositeFieldPath
	// This should be detected as a status read

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xmyresources.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "MyResource",
					"plural": "myresources",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"aws": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"kmsKeyArn": map[string]interface{}{
														"type": "string",
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

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "my-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "MyResource",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "kms-key",
									"base": map[string]interface{}{
										"apiVersion": "kms.aws.upbound.io/v1beta1",
										"kind":       "Key",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.arn",
											"toFieldPath":   "status.aws.kmsKeyArn", // Writes to status
										},
									},
								},
								map[string]interface{}{
									"name": "eks-cluster",
									"base": map[string]interface{}{
										"apiVersion": "eks.aws.upbound.io/v1beta1",
										"kind":       "Cluster",
									},
									"patches": []interface{}{
										// NO "type" field - defaults to FromCompositeFieldPath
										map[string]interface{}{
											"fromFieldPath": "status.aws.kmsKeyArn", // Reads from status!
											"toFieldPath":   "spec.forProvider.encryptionConfig.provider.keyArn",
											"policy": map[string]interface{}{
												"fromFieldPath": "Required",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{xrd})
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have NO warnings about unused status.aws.kmsKeyArn
	for _, issue := range issues {
		if strings.Contains(issue.Message, "status.aws.kmsKeyArn") && strings.Contains(issue.Message, "never read") {
			t.Errorf("False positive: status.aws.kmsKeyArn is used by default-type patch but flagged as unused: %s", issue.Message)
		}
	}
}

func TestStatusChainValidator_ParentReadsFromChildStatus(t *testing.T) {
	// Full end-to-end test: Parent reads status.vpcId from Child via ToCompositeFieldPath
	// Child composition writes to status.vpcId via ToCompositeFieldPath
	// This should pass with NO errors

	// Child XRD (defines status.vpcId)
	childXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xnetworkings.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "Networking",
					"plural": "networkings",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"vpcId": map[string]interface{}{
												"type": "string",
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

	// Child Composition (DOES write to status.vpcId via ToCompositeFieldPath)
	childComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "networking-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "Networking",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "vpc",
									"base": map[string]interface{}{
										"apiVersion": "ec2.aws.upbound.io/v1beta1",
										"kind":       "VPC",
									},
									"patches": []interface{}{
										// Child writes to its own status via ToCompositeFieldPath
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.id",
											"toFieldPath":   "status.vpcId",
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

	// Parent XRD (defines status.vpcId to receive from child)
	parentXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xplatforms.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "Platform",
					"plural": "platforms",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"vpcId": map[string]interface{}{
												"type": "string",
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

	// Parent Composition (reads status.vpcId from child Networking XR)
	parentComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "platform-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "Platform",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "networking",
									"base": map[string]interface{}{
										"apiVersion": "example.com/v1alpha1",
										"kind":       "Networking", // Child XR
									},
									"patches": []interface{}{
										// Parent reads from child's status via ToCompositeFieldPath
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.vpcId",     // Read from child's status
											"toFieldPath":   "status.vpcId",     // Write to parent's status
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
	err := parser.Parse([]*unstructured.Unstructured{childComposition, parentComposition, childXRD, parentXRD})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{childXRD, parentXRD})
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have NO errors - the chain is complete
	errorCount := 0
	for _, issue := range issues {
		if issue.Severity == "error" {
			t.Errorf("Unexpected error: %s", issue.Message)
			errorCount++
		}
	}
	if errorCount > 0 {
		t.Fatalf("Expected no errors for valid status chain, got %d", errorCount)
	}
}

func TestStatusChainValidator_ChildDoesNotWriteStatusField(t *testing.T) {
	// Parent reads status.vpcId from Child, but Child composition NEVER writes to it
	// This should produce an ERROR

	// Child XRD (defines status.vpcId)
	childXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xnetworkings.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "Networking",
					"plural": "networkings",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"vpcId": map[string]interface{}{
												"type": "string",
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

	// Child Composition (does NOT write to status.vpcId - THIS IS THE BUG!)
	childComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "networking-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "Networking",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "vpc",
									"base": map[string]interface{}{
										"apiVersion": "ec2.aws.upbound.io/v1beta1",
										"kind":       "VPC",
									},
									"patches": []interface{}{
										// NO STATUS WRITE! This is the bug.
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Parent XRD
	parentXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xplatforms.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "Platform",
					"plural": "platforms",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"vpcId": map[string]interface{}{
												"type": "string",
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

	// Parent Composition (tries to read status.vpcId from child)
	parentComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "platform-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "Platform",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "networking",
									"base": map[string]interface{}{
										"apiVersion": "example.com/v1alpha1",
										"kind":       "Networking",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.vpcId",     // Read from child's status
											"toFieldPath":   "status.vpcId",     // Write to parent's status
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
	err := parser.Parse([]*unstructured.Unstructured{childComposition, parentComposition, childXRD, parentXRD})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{childXRD, parentXRD})
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have at least 1 ERROR about child not writing to status.vpcId
	foundError := false
	for _, issue := range issues {
		if issue.Severity == "error" && strings.Contains(issue.Message, "never writes to this status field") {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("Expected error about child composition not writing to status.vpcId")
	}
}

func TestStatusChainValidator_ChildXRDDoesNotDefineField(t *testing.T) {
	// Parent reads status.vpcId from Child, but Child XRD doesn't define this field
	// This should produce an ERROR

	// Child XRD (does NOT define status.vpcId - THIS IS THE BUG!)
	childXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xnetworkings.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "Networking",
					"plural": "networkings",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											// NO vpcId! This is the bug.
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

	// Child Composition (writes to status.vpcId but XRD doesn't define it)
	childComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "networking-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "Networking",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "vpc",
									"base": map[string]interface{}{
										"apiVersion": "ec2.aws.upbound.io/v1beta1",
										"kind":       "VPC",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.atProvider.id",
											"toFieldPath":   "status.vpcId", // XRD doesn't define this!
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

	// Parent XRD
	parentXRD := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xplatforms.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "Platform",
					"plural": "platforms",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":       "object",
										"properties": map[string]interface{}{},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"vpcId": map[string]interface{}{
												"type": "string",
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

	// Parent Composition
	parentComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "platform-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "Platform",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "networking",
									"base": map[string]interface{}{
										"apiVersion": "example.com/v1alpha1",
										"kind":       "Networking",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "ToCompositeFieldPath",
											"fromFieldPath": "status.vpcId",
											"toFieldPath":   "status.vpcId",
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
	err := parser.Parse([]*unstructured.Unstructured{childComposition, parentComposition, childXRD, parentXRD})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	crds := ConvertXRDsToCRDs([]*unstructured.Unstructured{childXRD, parentXRD})
	validator := NewStatusChainValidator(parser.GetCompositions(), crds)
	issues := validator.Validate()

	// Should have at least 1 ERROR about child XRD not defining status.vpcId
	foundError := false
	for _, issue := range issues {
		if issue.Severity == "error" && strings.Contains(issue.Message, "doesn't define this field") {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("Expected error about child XRD not defining status.vpcId field")
	}
}

// =========================================
// Patch Type Validation Tests
// =========================================

func TestPatchTypeValidator_CombineFromCompositeWithoutCombine(t *testing.T) {
	// CombineFromComposite without combine field - should error

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										// CombineFromComposite without 'combine' field!
										map[string]interface{}{
											"type":        "CombineFromComposite",
											"toFieldPath": "spec.forProvider.name",
											// Missing: combine!
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type":       "object",
								"properties": map[string]interface{}{},
							},
						},
					},
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if len(result.Errors) == 0 {
		t.Fatal("Expected error for CombineFromComposite without combine, got none")
	}

	foundCombineError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "requires 'combine' field") {
			foundCombineError = true
			break
		}
	}
	if !foundCombineError {
		t.Errorf("Expected error about missing 'combine' field, got: %v", result.Errors)
	}
}

func TestPatchTypeValidator_CombineFromCompositeWithoutStrategy(t *testing.T) {
	// CombineFromComposite with combine but without strategy

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":        "CombineFromComposite",
											"toFieldPath": "spec.forProvider.name",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{
														"fromFieldPath": "spec.parameters.foo",
													},
												},
												// Missing: strategy!
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type":       "object",
								"properties": map[string]interface{}{},
							},
						},
					},
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	foundStrategyError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "requires 'combine.strategy'") {
			foundStrategyError = true
			break
		}
	}
	if !foundStrategyError {
		t.Errorf("Expected error about missing 'combine.strategy', got: %v", result.Errors)
	}
}

func TestPatchTypeValidator_ValidCombineFromComposite(t *testing.T) {
	// Valid CombineFromComposite - should have no errors

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":        "CombineFromComposite",
											"toFieldPath": "spec.forProvider.name",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{
														"fromFieldPath": "spec.parameters.foo",
													},
													map[string]interface{}{
														"fromFieldPath": "spec.parameters.bar",
													},
												},
												"strategy": "string",
												"string": map[string]interface{}{
													"fmt": "%s-%s",
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type":       "object",
								"properties": map[string]interface{}{},
							},
						},
					},
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if len(result.Errors) > 0 {
		t.Errorf("Expected no errors for valid CombineFromComposite, got: %v", result.Errors)
	}
}

func TestPatchTypeValidator_CombineFromCompositeFormatStringMismatch(t *testing.T) {
	// CombineFromComposite with mismatched variable count vs placeholder count - should error
	// This is the EBS CSI driver IAM role trust policy case

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type": "CombineFromComposite",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{"fromFieldPath": "spec.accountId"},
													map[string]interface{}{"fromFieldPath": "status.oidcHostname"},
													map[string]interface{}{"fromFieldPath": "status.oidcId"},
													map[string]interface{}{"fromFieldPath": "status.oidcHostname"},
													map[string]interface{}{"fromFieldPath": "status.oidcId"}, // 5 variables
												},
												"strategy": "string",
												"string": map[string]interface{}{
													"fmt": `{
  "Principal": {"Federated": "arn:aws:iam::%s:oidc-provider/%s"},
  "Condition": {"%s:aud": "sts.amazonaws.com"}
}`, // Only 3 placeholders!
												},
											},
											"toFieldPath": "spec.forProvider.assumeRolePolicy",
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "testxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if len(result.Errors) == 0 {
		t.Fatal("Expected error for format string mismatch, got none")
	}

	found := false
	for _, err := range result.Errors {
		if strings.Contains(err.Message, "format string has 3 placeholder(s)") &&
			strings.Contains(err.Message, "5 variable(s) defined") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected error about placeholder/variable mismatch, got: %v", result.Errors)
	}
}

func TestPatchTypeValidator_CombineFromCompositeValidFormatString(t *testing.T) {
	// CombineFromComposite with matching variable count and placeholder count - should pass

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type": "CombineFromComposite",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{"fromFieldPath": "spec.accountId"},
													map[string]interface{}{"fromFieldPath": "status.oidcHostname"},
													map[string]interface{}{"fromFieldPath": "status.oidcHostname"},
													map[string]interface{}{"fromFieldPath": "status.oidcHostname"},
												},
												"strategy": "string",
												"string": map[string]interface{}{
													"fmt": `{
  "Principal": {"Federated": "arn:aws:iam::%s:oidc-provider/%s"},
  "Condition": {
    "%s:aud": "sts.amazonaws.com",
    "%s:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa"
  }
}`, // 4 placeholders matching 4 variables
												},
											},
											"toFieldPath": "spec.forProvider.assumeRolePolicy",
											"policy": map[string]interface{}{
												"fromFieldPath": "Required",
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "testxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should have no errors for matching count
	if len(result.Errors) > 0 {
		t.Errorf("Expected no errors for valid format string, got: %v", result.Errors)
	}
}

func TestPatchTypeValidator_CombineFromCompositeInvalidJSON(t *testing.T) {
	// CombineFromComposite with invalid JSON template - should warn

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type": "CombineFromComposite",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{"fromFieldPath": "spec.value"},
												},
												"strategy": "string",
												"string": map[string]interface{}{
													"fmt": `{
  "key": "%s",
  trailing: "comma",
}`, // Invalid JSON - missing quotes around key
												},
											},
											"toFieldPath": "spec.forProvider.assumeRolePolicy",
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "testxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should have a warning for invalid JSON (warnings are now in result.Warnings)
	found := false
	for _, warn := range result.Warnings {
		if strings.Contains(warn.Message, "invalid JSON") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected warning about invalid JSON, got warnings: %v, errors: %v", result.Warnings, result.Errors)
	}
}

func TestPatchTypeValidator_CombineFromCompositeNoFormatString(t *testing.T) {
	// CombineFromComposite without string.fmt - should still pass basic validation

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type": "CombineFromComposite",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{"fromFieldPath": "spec.value"},
												},
												"strategy": "string",
												// No string.fmt specified
											},
											"toFieldPath": "spec.forProvider.value",
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "testxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should have no errors - format string validation is optional
	if len(result.Errors) > 0 {
		t.Errorf("Expected no errors when format string is not specified, got: %v", result.Errors)
	}
}

func TestPatchTypeValidator_FromCompositeWithoutFromFieldPath(t *testing.T) {
	// FromCompositeFieldPath without fromFieldPath - should error

	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-comp",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":        "FromCompositeFieldPath",
											"toFieldPath": "spec.forProvider.name",
											// Missing: fromFieldPath!
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type":       "object",
								"properties": map[string]interface{}{},
							},
						},
					},
				},
			},
		},
	}

	parser := NewCompositionParser()
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	foundError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "requires 'fromFieldPath'") {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Errorf("Expected error about missing 'fromFieldPath', got: %v", result.Errors)
	}
}

// =============================================================================
// Composition Selector Validation Tests
// =============================================================================

func TestCompositionSelectorValidator_ValidSelector(t *testing.T) {
	// Create composition with labels
	parentComp := &ParsedComposition{
		Name:             "stamp-common",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels: map[string]string{
			"provider": "aws",
			"region":   "us-west-2",
		},
	}

	// Create child composition with matching selector
	childComp := &ParsedComposition{
		Name:             "stamp-cluster",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRChild"},
		Labels: map[string]string{
			"provider": "aws",
		},
		Resources: []ComposedResource{
			{
				Name: "cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRParent",
					},
				},
				CompositionSelector: map[string]string{
					"provider": "aws",
				},
			},
		},
	}

	validator := NewCompositionSelectorValidator([]*ParsedComposition{parentComp, childComp})
	errors := validator.Validate()

	// Filter only actual errors (not warnings)
	var actualErrors []CompositionSelectorError
	for _, err := range errors {
		if err.Severity == "error" {
			actualErrors = append(actualErrors, err)
		}
	}

	if len(actualErrors) > 0 {
		t.Errorf("Expected no errors, got: %v", actualErrors)
	}
}

func TestCompositionSelectorValidator_NoMatchingComposition(t *testing.T) {
	// Create composition with labels
	parentComp := &ParsedComposition{
		Name:             "stamp-common-aws",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels: map[string]string{
			"provider": "aws",
		},
	}

	// Create child composition with non-matching selector (typo)
	childComp := &ParsedComposition{
		Name:             "stamp-cluster",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRChild"},
		Resources: []ComposedResource{
			{
				Name: "cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRParent",
					},
				},
				CompositionSelector: map[string]string{
					"provider": "awss", // Typo!
				},
			},
		},
	}

	validator := NewCompositionSelectorValidator([]*ParsedComposition{parentComp, childComp})
	allIssues := validator.Validate()

	// Filter only actual errors (not warnings)
	var errors []CompositionSelectorError
	for _, issue := range allIssues {
		if issue.Severity == "error" {
			errors = append(errors, issue)
		}
	}

	if len(errors) != 1 {
		t.Fatalf("Expected 1 error, got %d: %v", len(errors), errors)
	}

	err := errors[0]
	if err.Severity != "error" {
		t.Errorf("Expected severity 'error', got: %s", err.Severity)
	}
	if !strings.Contains(err.Message, "no composition") {
		t.Errorf("Expected error about no matching composition, got: %s", err.Message)
	}
	if err.CompositionName != "stamp-cluster" {
		t.Errorf("Expected composition name 'stamp-cluster', got: %s", err.CompositionName)
	}
	if err.ResourceName != "cluster" {
		t.Errorf("Expected resource name 'cluster', got: %s", err.ResourceName)
	}
}

func TestCompositionSelectorValidator_MultiLabelSelector(t *testing.T) {
	// Create compositions with different label combinations
	awsProdComp := &ParsedComposition{
		Name:             "stamp-common-aws-prod",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels: map[string]string{
			"provider":    "aws",
			"environment": "prod",
		},
	}

	awsDevComp := &ParsedComposition{
		Name:             "stamp-common-aws-dev",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels: map[string]string{
			"provider":    "aws",
			"environment": "dev",
		},
	}

	// Create child that selects specifically aws+prod
	childComp := &ParsedComposition{
		Name:             "stamp-cluster",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRChild"},
		Resources: []ComposedResource{
			{
				Name: "common",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRParent",
					},
				},
				CompositionSelector: map[string]string{
					"provider":    "aws",
					"environment": "prod",
				},
			},
		},
	}

	validator := NewCompositionSelectorValidator([]*ParsedComposition{awsProdComp, awsDevComp, childComp})
	allIssues := validator.Validate()

	// Filter only actual errors (not warnings)
	var errors []CompositionSelectorError
	for _, issue := range allIssues {
		if issue.Severity == "error" {
			errors = append(errors, issue)
		}
	}

	// Should match awsProdComp only (no errors)
	if len(errors) > 0 {
		t.Errorf("Expected no errors, got: %v", errors)
	}

	// Verify awsProdComp was selected (no unused warning for it)
	for _, issue := range allIssues {
		if issue.CompositionName == "stamp-common-aws-prod" && issue.Severity == "warning" {
			t.Errorf("awsProdComp should be selected, but got warning: %v", issue)
		}
	}
}

func TestCompositionSelectorValidator_UnusedComposition(t *testing.T) {
	// Create composition with labels but never selected
	unusedComp := &ParsedComposition{
		Name:             "stamp-common-azure",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels: map[string]string{
			"provider": "azure",
		},
	}

	// Create composition with AWS labels
	awsComp := &ParsedComposition{
		Name:             "stamp-common-aws",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels: map[string]string{
			"provider": "aws",
		},
	}

	// Create child that only selects AWS
	childComp := &ParsedComposition{
		Name:             "stamp-cluster",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRChild"},
		Resources: []ComposedResource{
			{
				Name: "common",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRParent",
					},
				},
				CompositionSelector: map[string]string{
					"provider": "aws",
				},
			},
		},
	}

	validator := NewCompositionSelectorValidator([]*ParsedComposition{unusedComp, awsComp, childComp})
	errors := validator.Validate()

	// Should have 1 warning about unused Azure composition
	if len(errors) != 1 {
		t.Fatalf("Expected 1 warning, got %d: %v", len(errors), errors)
	}

	err := errors[0]
	if err.Severity != "warning" {
		t.Errorf("Expected severity 'warning', got: %s", err.Severity)
	}
	if err.CompositionName != "stamp-common-azure" {
		t.Errorf("Expected composition name 'stamp-common-azure', got: %s", err.CompositionName)
	}
	if !strings.Contains(err.Message, "never selected") {
		t.Errorf("Expected warning about never selected, got: %s", err.Message)
	}
}

func TestCompositionSelectorValidator_NoLabelsNoWarning(t *testing.T) {
	// Composition without labels should not trigger "unused" warning
	noLabelsComp := &ParsedComposition{
		Name:             "stamp-common-default",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels:           map[string]string{}, // Empty labels
	}

	// No children referencing it
	validator := NewCompositionSelectorValidator([]*ParsedComposition{noLabelsComp})
	errors := validator.Validate()

	// Should have NO warnings (can't select by labels if there are none)
	if len(errors) != 0 {
		t.Errorf("Expected no warnings for composition without labels, got: %v", errors)
	}
}

func TestCompositionSelectorValidator_WrongKind(t *testing.T) {
	// Create composition of different kind
	networkingComp := &ParsedComposition{
		Name:             "stamp-networking",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRNetworking"},
		Labels: map[string]string{
			"provider": "aws",
		},
	}

	// Child tries to select XRParent with matching labels
	childComp := &ParsedComposition{
		Name:             "stamp-cluster",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRChild"},
		Resources: []ComposedResource{
			{
				Name: "common",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRParent", // Different kind!
					},
				},
				CompositionSelector: map[string]string{
					"provider": "aws",
				},
			},
		},
	}

	validator := NewCompositionSelectorValidator([]*ParsedComposition{networkingComp, childComp})
	errors := validator.Validate()

	// Should error - labels match but kind doesn't
	if len(errors) == 0 {
		t.Fatal("Expected error for kind mismatch, got none")
	}

	foundKindError := false
	for _, err := range errors {
		if err.Severity == "error" && strings.Contains(err.Message, "no composition") {
			foundKindError = true
		}
	}
	if !foundKindError {
		t.Errorf("Expected error about no composition of correct kind, got: %v", errors)
	}
}

func TestCompositionSelectorValidator_EmptySelectorMatchesNothing(t *testing.T) {
	// Create composition with labels
	comp := &ParsedComposition{
		Name:             "stamp-common",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRParent"},
		Labels: map[string]string{
			"provider": "aws",
		},
	}

	// Child with empty selector
	childComp := &ParsedComposition{
		Name:             "stamp-cluster",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRChild"},
		Resources: []ComposedResource{
			{
				Name: "common",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRParent",
					},
				},
				CompositionSelector: map[string]string{}, // Empty!
			},
		},
	}

	validator := NewCompositionSelectorValidator([]*ParsedComposition{comp, childComp})
	allIssues := validator.Validate()

	// Filter only actual errors (not warnings)
	var errors []CompositionSelectorError
	for _, issue := range allIssues {
		if issue.Severity == "error" {
			errors = append(errors, issue)
		}
	}

	// Empty selector should NOT match anything (must be explicit)
	if len(errors) == 0 {
		t.Fatal("Expected error for empty selector, got none")
	}

	foundError := false
	for _, err := range errors {
		if strings.Contains(err.Message, "no composition") {
			foundError = true
		}
	}
	if !foundError {
		t.Errorf("Expected error about no matching composition for empty selector, got: %v", errors)
	}
}

func TestCompositionParser_ExtractsCompositionSelector(t *testing.T) {
	compYAML := `
apiVersion: apiextensions.crossplane.io/v1
kind: Composition
metadata:
  name: test-comp
spec:
  compositeTypeRef:
    apiVersion: example.com/v1alpha1
    kind: TestStamp
  mode: Pipeline
  pipeline:
    - step: patch-and-transform
      functionRef:
        name: crossplane-contrib-function-patch-and-transform
      input:
        apiVersion: pt.fn.crossplane.io/v1beta1
        kind: Resources
        resources:
          - name: child-xr
            base:
              apiVersion: example.com/v1alpha1
              kind: ChildStamp
              spec:
                compositionSelector:
                  matchLabels:
                    provider: aws
                    region: us-west-2
`
	var obj unstructured.Unstructured
	if err := yaml.Unmarshal([]byte(compYAML), &obj); err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Ensure GVK is set (yaml.Unmarshal may not set it)
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "apiextensions.crossplane.io",
		Version: "v1",
		Kind:    "Composition",
	})

	parser := NewCompositionParser()
	if err := parser.Parse([]*unstructured.Unstructured{&obj}); err != nil {
		t.Fatalf("Failed to parse composition: %v", err)
	}

	comps := parser.GetCompositions()
	if len(comps) != 1 {
		t.Fatalf("Expected 1 composition, got %d", len(comps))
	}

	comp := comps[0]
	if len(comp.Resources) != 1 {
		t.Fatalf("Expected 1 resource, got %d", len(comp.Resources))
	}

	res := comp.Resources[0]
	if res.Name != "child-xr" {
		t.Errorf("Expected resource name 'child-xr', got: %s", res.Name)
	}

	if res.CompositionSelector == nil {
		t.Fatal("Expected compositionSelector to be extracted, but got nil")
	}

	if res.CompositionSelector["provider"] != "aws" {
		t.Errorf("Expected provider=aws, got: %s", res.CompositionSelector["provider"])
	}

	if res.CompositionSelector["region"] != "us-west-2" {
		t.Errorf("Expected region=us-west-2, got: %s", res.CompositionSelector["region"])
	}
}

// =============================================================================
// Dynamic Selector Tracing Tests (Option B)
// =============================================================================

func TestCompositionSelectorValidator_DynamicSelectorFromEnum(t *testing.T) {
	// This tests the real-world pattern where:
	// 1. Parent composition has spec.parameters.cloud with enum ["aws", "azure"]
	// 2. Patch sets compositionSelector.matchLabels.provider from spec.parameters.cloud
	// 3. Child compositions have labels provider=aws and provider=azure

	// AWS composition with label
	awsComp := &ParsedComposition{
		Name:             "stamp-cluster-aws",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCluster"},
		Labels: map[string]string{
			"provider": "aws",
		},
	}

	// Azure composition with label
	azureComp := &ParsedComposition{
		Name:             "stamp-cluster-azure",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCluster"},
		Labels: map[string]string{
			"provider": "azure",
		},
	}

	// Parent composition that dynamically selects based on spec.parameters.cloud
	parentComp := &ParsedComposition{
		Name:             "stamp-common",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCommon"},
		Resources: []ComposedResource{
			{
				Name: "cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRCluster",
						"spec": map[string]interface{}{
							"compositionSelector": map[string]interface{}{
								"matchLabels": map[string]interface{}{
									"provider": "", // Empty - will be patched
								},
							},
						},
					},
				},
				CompositionSelector: map[string]string{
					"provider": "", // Empty in base
				},
				Patches: []Patch{
					{
						Type:          PatchTypeFromCompositeFieldPath,
						FromFieldPath: "spec.parameters.cloud",
						ToFieldPath:   "spec.compositionSelector.matchLabels.provider",
					},
				},
			},
		},
	}

	// Create XRD with enum for cloud parameter
	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xrcommons.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "XRCommon",
					"plural": "xrcommons",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":    "v1alpha1",
						"served":  true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"parameters": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"cloud": map[string]interface{}{
														"type": "string",
														"enum": []interface{}{"aws", "azure"},
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

	validator := NewCompositionSelectorValidator([]*ParsedComposition{awsComp, azureComp, parentComp})
	validator.SetXRDSchemas([]*unstructured.Unstructured{xrd})
	errors := validator.Validate()

	// Should have NO errors and NO warnings about unused compositions
	// because both aws and azure compositions are reachable via the enum values
	for _, err := range errors {
		if err.Severity == "error" {
			t.Errorf("Unexpected error: %v", err)
		}
		if err.Severity == "warning" && strings.Contains(err.Message, "never selected") {
			// This warning is now incorrect - the compositions ARE selected via dynamic patch
			t.Errorf("Unexpected 'never selected' warning: %v", err)
		}
	}
}

func TestCompositionSelectorValidator_DynamicSelectorMissingEnum(t *testing.T) {
	// Tests that we error when the dynamic selector enum value doesn't match any composition

	// Only AWS composition exists
	awsComp := &ParsedComposition{
		Name:             "stamp-cluster-aws",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCluster"},
		Labels: map[string]string{
			"provider": "aws",
		},
	}

	// Parent with dynamic selector that can select aws OR azure
	parentComp := &ParsedComposition{
		Name:             "stamp-common",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCommon"},
		Resources: []ComposedResource{
			{
				Name: "cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRCluster",
					},
				},
				CompositionSelector: map[string]string{
					"provider": "",
				},
				Patches: []Patch{
					{
						Type:          PatchTypeFromCompositeFieldPath,
						FromFieldPath: "spec.parameters.cloud",
						ToFieldPath:   "spec.compositionSelector.matchLabels.provider",
					},
				},
			},
		},
	}

	// XRD with enum that includes azure (but no azure composition exists!)
	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xrcommons.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "XRCommon",
					"plural": "xrcommons",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":    "v1alpha1",
						"served":  true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"parameters": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"cloud": map[string]interface{}{
														"type": "string",
														"enum": []interface{}{"aws", "azure"},
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

	validator := NewCompositionSelectorValidator([]*ParsedComposition{awsComp, parentComp})
	validator.SetXRDSchemas([]*unstructured.Unstructured{xrd})
	errors := validator.Validate()

	// Should have an error because azure composition doesn't exist
	foundAzureError := false
	for _, err := range errors {
		if err.Severity == "error" && strings.Contains(err.Message, "azure") {
			foundAzureError = true
		}
	}

	if !foundAzureError {
		t.Error("Expected error about missing azure composition, got none")
	}
}

func TestCompositionSelectorValidator_DynamicSelectorWithTransform(t *testing.T) {
	// Tests that transforms on the patch are applied to enum values

	// Composition with uppercase label
	comp := &ParsedComposition{
		Name:             "stamp-cluster-AWS",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCluster"},
		Labels: map[string]string{
			"provider": "AWS", // Uppercase!
		},
	}

	// Parent with dynamic selector and map transform
	parentComp := &ParsedComposition{
		Name:             "stamp-common",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCommon"},
		Resources: []ComposedResource{
			{
				Name: "cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRCluster",
					},
				},
				CompositionSelector: map[string]string{
					"provider": "",
				},
				Patches: []Patch{
					{
						Type:          PatchTypeFromCompositeFieldPath,
						FromFieldPath: "spec.parameters.cloud",
						ToFieldPath:   "spec.compositionSelector.matchLabels.provider",
						Transforms: []Transform{
							{
								Type: "map",
								Map: map[string]string{
									"aws": "AWS", // Transform to uppercase
								},
							},
						},
					},
				},
			},
		},
	}

	// XRD with lowercase enum
	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xrcommons.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "XRCommon",
					"plural": "xrcommons",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":    "v1alpha1",
						"served":  true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"parameters": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"cloud": map[string]interface{}{
														"type": "string",
														"enum": []interface{}{"aws"}, // lowercase
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

	validator := NewCompositionSelectorValidator([]*ParsedComposition{comp, parentComp})
	validator.SetXRDSchemas([]*unstructured.Unstructured{xrd})
	errors := validator.Validate()

	// Should have no errors - aws maps to AWS which matches the composition
	for _, err := range errors {
		if err.Severity == "error" {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}

func TestCompositionSelectorValidator_ExtractSelectorLabelKey(t *testing.T) {
	validator := NewCompositionSelectorValidator(nil)

	tests := []struct {
		toFieldPath string
		wantKey     string
	}{
		{
			toFieldPath: "spec.compositionSelector.matchLabels.provider",
			wantKey:     "provider",
		},
		{
			toFieldPath: "spec.crossplane.compositionSelector.matchLabels.provider",
			wantKey:     "provider",
		},
		{
			toFieldPath: "spec.compositionSelector.matchLabels.region",
			wantKey:     "region",
		},
		{
			toFieldPath: "spec.forProvider.region", // Not a selector
			wantKey:     "",
		},
		{
			toFieldPath: "spec.parameters.cloud", // Not a selector
			wantKey:     "",
		},
		// Bracket notation tests
		{
			toFieldPath: `spec.crossplane.compositionSelector.matchLabels["azure-logging-enabled"]`,
			wantKey:     "azure-logging-enabled",
		},
		{
			toFieldPath: `spec.compositionSelector.matchLabels["flow-logs-enabled"]`,
			wantKey:     "flow-logs-enabled",
		},
		{
			toFieldPath: `spec.crossplane.compositionSelector.matchLabels[provider]`,
			wantKey:     "provider",
		},
	}

	for _, tc := range tests {
		t.Run(tc.toFieldPath, func(t *testing.T) {
			got := validator.extractSelectorLabelKey(tc.toFieldPath)
			if got != tc.wantKey {
				t.Errorf("extractSelectorLabelKey(%q) = %q, want %q", tc.toFieldPath, got, tc.wantKey)
			}
		})
	}
}

func TestCompositionSelectorValidator_NoXRDSchemaStillWorks(t *testing.T) {
	// When no XRD schema is provided, dynamic selectors can't be traced
	// but static selectors should still work

	awsComp := &ParsedComposition{
		Name:             "stamp-cluster-aws",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCluster"},
		Labels: map[string]string{
			"provider": "aws",
		},
	}

	// Static selector (no patch)
	parentComp := &ParsedComposition{
		Name:             "stamp-common",
		CompositeTypeRef: schema.GroupVersionKind{Group: "example.com", Version: "v1alpha1", Kind: "XRCommon"},
		Resources: []ComposedResource{
			{
				Name: "cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "example.com/v1alpha1",
						"kind":       "XRCluster",
					},
				},
				CompositionSelector: map[string]string{
					"provider": "aws",
				},
			},
		},
	}

	validator := NewCompositionSelectorValidator([]*ParsedComposition{awsComp, parentComp})
	// No XRD schema set!
	errors := validator.Validate()

	// Should work fine with static selector
	for _, err := range errors {
		if err.Severity == "error" {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}

// =============================================================================
// Patch Type Mismatch Validation Tests
// =============================================================================

func TestPatchTypeMismatchValidator_StringToInteger(t *testing.T) {
	// Create a navigator with mock schemas
	navigator := &SchemaNavigator{
		schemas: make(map[schema.GroupVersionKind]*extv1.JSONSchemaProps),
	}

	// XR schema with string parameter
	xrGVK := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "TestXR"}
	navigator.schemas[xrGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"parameters": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"count": {Type: "string"}, // String in XR
						},
					},
				},
			},
		},
	}

	// Target resource schema with integer field
	targetGVK := schema.GroupVersionKind{Group: "aws.upbound.io", Version: "v1beta1", Kind: "Instance"}
	navigator.schemas[targetGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"forProvider": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"instanceCount": {Type: "integer"}, // Integer in target!
						},
					},
				},
			},
		},
	}

	compositions := []*ParsedComposition{
		{
			Name:             "test-comp",
			CompositeTypeRef: xrGVK,
			Resources: []ComposedResource{
				{
					Name: "instance",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "aws.upbound.io/v1beta1",
							"kind":       "Instance",
						},
					},
					BaseGVK: targetGVK,
					Patches: []Patch{
						{
							Type:          PatchTypeFromCompositeFieldPath,
							FromFieldPath: "spec.parameters.count",
							ToFieldPath:   "spec.forProvider.instanceCount",
						},
					},
				},
			},
		},
	}

	validator := NewPatchTypeMismatchValidator(navigator, compositions)
	errors := validator.Validate()

	if len(errors) == 0 {
		t.Fatal("Expected type mismatch error, got none")
	}

	foundMismatch := false
	for _, err := range errors {
		if strings.Contains(err.Message, "type mismatch") {
			foundMismatch = true
			if !strings.Contains(err.Message, "string") || !strings.Contains(err.Message, "integer") {
				t.Errorf("Expected error to mention string→integer, got: %s", err.Message)
			}
		}
	}
	if !foundMismatch {
		t.Errorf("Expected type mismatch error, got: %v", errors)
	}
}

func TestPatchTypeMismatchValidator_IntegerToString(t *testing.T) {
	navigator := &SchemaNavigator{
		schemas: make(map[schema.GroupVersionKind]*extv1.JSONSchemaProps),
	}

	// XR schema with integer parameter
	xrGVK := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "TestXR"}
	navigator.schemas[xrGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"parameters": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"port": {Type: "integer"}, // Integer in XR
						},
					},
				},
			},
		},
	}

	// Target with string field
	targetGVK := schema.GroupVersionKind{Group: "k8s.io", Version: "v1", Kind: "Service"}
	navigator.schemas[targetGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"port": {Type: "string"}, // String in target
				},
			},
		},
	}

	compositions := []*ParsedComposition{
		{
			Name:             "test-comp",
			CompositeTypeRef: xrGVK,
			Resources: []ComposedResource{
				{
					Name:    "svc",
					BaseGVK: targetGVK,
					Patches: []Patch{
						{
							Type:          PatchTypeFromCompositeFieldPath,
							FromFieldPath: "spec.parameters.port",
							ToFieldPath:   "spec.port",
						},
					},
				},
			},
		},
	}

	validator := NewPatchTypeMismatchValidator(navigator, compositions)
	errors := validator.Validate()

	// Integer → String should be allowed (can stringify)
	if len(errors) > 0 {
		t.Errorf("Expected no errors (int can convert to string), got: %v", errors)
	}
}

func TestPatchTypeMismatchValidator_WithConvertTransform(t *testing.T) {
	navigator := &SchemaNavigator{
		schemas: make(map[schema.GroupVersionKind]*extv1.JSONSchemaProps),
	}

	// XR with integer
	xrGVK := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "TestXR"}
	navigator.schemas[xrGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"parameters": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"replicas": {Type: "integer"},
						},
					},
				},
			},
		},
	}

	// Target with string
	targetGVK := schema.GroupVersionKind{Group: "k8s.io", Version: "v1", Kind: "ConfigMap"}
	navigator.schemas[targetGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"data": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"replicas": {Type: "string"},
				},
			},
		},
	}

	compositions := []*ParsedComposition{
		{
			Name:             "test-comp",
			CompositeTypeRef: xrGVK,
			Resources: []ComposedResource{
				{
					Name:    "cm",
					BaseGVK: targetGVK,
					Patches: []Patch{
						{
							Type:          PatchTypeFromCompositeFieldPath,
							FromFieldPath: "spec.parameters.replicas",
							ToFieldPath:   "data.replicas",
							Transforms: []Transform{
								{
									Type: "convert",
									Convert: &ConvertTransform{
										ToType: "string", // Explicitly convert to string
									},
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewPatchTypeMismatchValidator(navigator, compositions)
	errors := validator.Validate()

	// Should NOT error because transform converts int → string
	if len(errors) > 0 {
		t.Errorf("Expected no errors (convert transform handles type), got: %v", errors)
	}
}

func TestPatchTypeMismatchValidator_MapThenConvertTransform(t *testing.T) {
	navigator := &SchemaNavigator{
		schemas: make(map[schema.GroupVersionKind]*extv1.JSONSchemaProps),
	}

	// XR with string environment parameter (values: "dev", "prod")
	xrGVK := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "TestXR"}
	navigator.schemas[xrGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"parameters": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"environment": {Type: "string"}, // "dev" or "prod"
						},
					},
				},
			},
		},
	}

	// Target resource with boolean field
	targetGVK := schema.GroupVersionKind{Group: "aws.io", Version: "v1", Kind: "DBCluster"}
	navigator.schemas[targetGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"forProvider": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"performanceInsightsEnabled": {Type: "boolean"},
						},
					},
				},
			},
		},
	}

	compositions := []*ParsedComposition{
		{
			Name:             "test-comp",
			CompositeTypeRef: xrGVK,
			Resources: []ComposedResource{
				{
					Name:    "db",
					BaseGVK: targetGVK,
					Patches: []Patch{
						{
							Type:          PatchTypeFromCompositeFieldPath,
							FromFieldPath: "spec.parameters.environment",
							ToFieldPath:   "spec.forProvider.performanceInsightsEnabled",
							Transforms: []Transform{
								{
									Type: "map",
									// Map "dev" → "false", "prod" → "true" (strings)
								},
								{
									Type: "convert",
									Convert: &ConvertTransform{
										ToType: "bool", // Note: uses "bool" not "boolean"
									},
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewPatchTypeMismatchValidator(navigator, compositions)
	errors := validator.Validate()

	// Should NOT error because:
	// 1. string → map → string ("false"/"true")
	// 2. string → convert(bool) → boolean
	// 3. boolean matches target boolean
	if len(errors) > 0 {
		t.Errorf("Expected no errors (map → convert transform chain should work), got: %v", errors)
	}
}

func TestPatchTypeMismatchValidator_CompatibleTypes(t *testing.T) {
	navigator := &SchemaNavigator{
		schemas: make(map[schema.GroupVersionKind]*extv1.JSONSchemaProps),
	}

	// Both string
	xrGVK := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "TestXR"}
	navigator.schemas[xrGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"spec": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"parameters": {
						Type: "object",
						Properties: map[string]extv1.JSONSchemaProps{
							"name": {Type: "string"},
						},
					},
				},
			},
		},
	}

	targetGVK := schema.GroupVersionKind{Group: "k8s.io", Version: "v1", Kind: "ConfigMap"}
	navigator.schemas[targetGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"metadata": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"name": {Type: "string"},
				},
			},
		},
	}

	compositions := []*ParsedComposition{
		{
			Name:             "test-comp",
			CompositeTypeRef: xrGVK,
			Resources: []ComposedResource{
				{
					Name:    "cm",
					BaseGVK: targetGVK,
					Patches: []Patch{
						{
							Type:          PatchTypeFromCompositeFieldPath,
							FromFieldPath: "spec.parameters.name",
							ToFieldPath:   "metadata.name",
						},
					},
				},
			},
		},
	}

	validator := NewPatchTypeMismatchValidator(navigator, compositions)
	errors := validator.Validate()

	if len(errors) > 0 {
		t.Errorf("Expected no errors for string→string, got: %v", errors)
	}
}

func TestPatchTypeMismatchValidator_StatusTypeMismatch(t *testing.T) {
	navigator := &SchemaNavigator{
		schemas: make(map[schema.GroupVersionKind]*extv1.JSONSchemaProps),
	}

	// Parent XR schema with integer status field
	parentGVK := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "ParentXR"}
	navigator.schemas[parentGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"status": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"data": {Type: "integer"}, // Integer in parent
				},
			},
		},
	}

	// Child XR schema with object status field (incompatible with integer!)
	childGVK := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "ChildXR"}
	navigator.schemas[childGVK] = &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"status": {
				Type: "object",
				Properties: map[string]extv1.JSONSchemaProps{
					"data": {Type: "object"}, // Object in child - incompatible with integer!
				},
			},
		},
	}

	compositions := []*ParsedComposition{
		{
			Name:             "parent-comp",
			CompositeTypeRef: parentGVK,
			Resources: []ComposedResource{
				{
					Name:    "child",
					BaseGVK: childGVK,
				},
			},
			AllPatches: []PatchInfo{
				{
					CompositionName: "parent-comp",
					ResourceName:    "child",
					PatchIndex:      0,
					Patch: Patch{
						Type:          PatchTypeToCompositeFieldPath,
						FromFieldPath: "status.data", // Read object from child
						ToFieldPath:   "status.data", // Write to integer in parent - MISMATCH!
					},
					SourceGVK: childGVK,
					TargetGVK: parentGVK,
				},
			},
		},
	}

	validator := NewPatchTypeMismatchValidator(navigator, compositions)
	errors := validator.ValidateStatusTypes()

	if len(errors) == 0 {
		t.Fatal("Expected status type mismatch error, got none")
	}

	foundMismatch := false
	for _, err := range errors {
		if strings.Contains(err.Message, "status type mismatch") {
			foundMismatch = true
			t.Logf("Found expected error: %s", err.Message)
		}
	}
	if !foundMismatch {
		t.Errorf("Expected status type mismatch error, got: %v", errors)
	}
}

// =============================================================================
// Status Dependency Policy Validation Tests
// =============================================================================

func TestPatchTypeValidator_StatusDependencyWithoutRequiredPolicy(t *testing.T) {
	// Patch reading from status.* without Required policy should warn
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-karpenter",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "helm-release",
									"base": map[string]interface{}{
										"apiVersion": "helm.crossplane.io/v1beta1",
										"kind":       "Release",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "status.controllerRoleArn",
											"toFieldPath":   "spec.forProvider.values.serviceAccount.annotations[eks.amazonaws.com/role-arn]",
											// Missing: policy.fromFieldPath: Required
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"controllerRoleArn": map[string]interface{}{
												"type": "string",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should have an error about status dependency without Required
	foundError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "status dependency") && strings.Contains(e.Message, "Required") {
			foundError = true
			t.Logf("Found expected error: %s", e.Message)
		}
	}
	if !foundError {
		t.Errorf("Expected error about status dependency without Required policy, got errors: %v", result.Errors)
	}
}

func TestPatchTypeValidator_StatusDependencyWithRequiredPolicy(t *testing.T) {
	// Patch reading from status.* WITH Required policy should NOT warn
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-karpenter-fixed",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "helm-release",
									"base": map[string]interface{}{
										"apiVersion": "helm.crossplane.io/v1beta1",
										"kind":       "Release",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "status.controllerRoleArn",
											"toFieldPath":   "spec.forProvider.values.serviceAccount.annotations[eks.amazonaws.com/role-arn]",
											"policy": map[string]interface{}{
												"fromFieldPath": "Required",
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"controllerRoleArn": map[string]interface{}{
												"type": "string",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should NOT have any error about status dependency
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "status dependency") {
			t.Errorf("Should not error about status dependency when Required policy is set, got: %s", e.Message)
		}
	}
}

func TestPatchTypeValidator_CombineStatusDependencyWithoutRequiredPolicy(t *testing.T) {
	// CombineFromComposite reading from status.* without Required policy should warn
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-iam-role",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "iam-role",
									"base": map[string]interface{}{
										"apiVersion": "iam.aws.upbound.io/v1beta1",
										"kind":       "Role",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type": "CombineFromComposite",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{"fromFieldPath": "spec.parameters.accountId"},
													map[string]interface{}{"fromFieldPath": "status.oidcIssuerHostname"}, // Status dependency!
													map[string]interface{}{"fromFieldPath": "status.oidcIssuerId"},       // Status dependency!
												},
												"strategy": "string",
												"string": map[string]interface{}{
													"fmt": `{"Federated": "arn:aws:iam::%s:oidc-provider/%s", "Condition": {"%s:aud": "sts"}}`,
												},
											},
											"toFieldPath": "spec.forProvider.assumeRolePolicy",
											// Missing: policy.fromFieldPath: Required
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"parameters": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"accountId": map[string]interface{}{
														"type": "string",
													},
												},
											},
										},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"oidcIssuerHostname": map[string]interface{}{
												"type": "string",
											},
											"oidcIssuerId": map[string]interface{}{
												"type": "string",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should have an error about status dependency without Required
	foundError := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "status dependency") || strings.Contains(e.Message, "status fields") {
			foundError = true
			t.Logf("Found expected error: %s", e.Message)
			// Verify it mentions both status fields
			if !strings.Contains(e.Message, "oidcIssuerHostname") || !strings.Contains(e.Message, "oidcIssuerId") {
				t.Logf("Error should mention all status fields being read")
			}
		}
	}
	if !foundError {
		t.Errorf("Expected error about CombineFromComposite status dependency without Required policy, got errors: %v", result.Errors)
	}
}

func TestPatchTypeValidator_CombineStatusDependencyWithRequiredPolicy(t *testing.T) {
	// CombineFromComposite reading from status.* WITH Required policy should NOT warn
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-iam-role-fixed",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "iam-role",
									"base": map[string]interface{}{
										"apiVersion": "iam.aws.upbound.io/v1beta1",
										"kind":       "Role",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type": "CombineFromComposite",
											"combine": map[string]interface{}{
												"variables": []interface{}{
													map[string]interface{}{"fromFieldPath": "spec.parameters.accountId"},
													map[string]interface{}{"fromFieldPath": "status.oidcIssuerHostname"},
													map[string]interface{}{"fromFieldPath": "status.oidcIssuerId"},
												},
												"strategy": "string",
												"string": map[string]interface{}{
													"fmt": `{"Federated": "arn:aws:iam::%s:oidc-provider/%s", "Condition": {"%s:aud": "sts"}}`,
												},
											},
											"toFieldPath": "spec.forProvider.assumeRolePolicy",
											"policy": map[string]interface{}{
												"fromFieldPath": "Required",
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"parameters": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"accountId": map[string]interface{}{
														"type": "string",
													},
												},
											},
										},
									},
									"status": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"oidcIssuerHostname": map[string]interface{}{
												"type": "string",
											},
											"oidcIssuerId": map[string]interface{}{
												"type": "string",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should NOT have any error about status dependency
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "status dependency") || strings.Contains(e.Message, "status fields") {
			t.Errorf("Should not error about status dependency when Required policy is set, got: %s", e.Message)
		}
	}
}

func TestPatchTypeValidator_SpecFieldWithoutRequiredPolicy(t *testing.T) {
	// Patch reading from spec.* (NOT status) should NOT warn even without Required
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-spec-only",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "example.com/v1alpha1",
					"kind":       "TestXR",
				},
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "patch-and-transform",
						"functionRef": map[string]interface{}{
							"name": "function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "test-resource",
									"base": map[string]interface{}{
										"apiVersion": "test.io/v1beta1",
										"kind":       "TestResource",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"type":          "FromCompositeFieldPath",
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.forProvider.region",
											// No policy - should be fine for spec.* fields
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

	xrd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "CompositeResourceDefinition",
			"metadata": map[string]interface{}{
				"name": "xtestxrs.example.com",
			},
			"spec": map[string]interface{}{
				"group": "example.com",
				"names": map[string]interface{}{
					"kind":   "TestXR",
					"plural": "testxrs",
				},
				"versions": []interface{}{
					map[string]interface{}{
						"name":          "v1alpha1",
						"served":        true,
						"referenceable": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"parameters": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"region": map[string]interface{}{
														"type": "string",
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
	err := parser.Parse([]*unstructured.Unstructured{composition, xrd})
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	validator := NewPatchTypeValidator(parser.GetCompositions())
	var buf strings.Builder
	result, err := validator.Validate(&buf)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should NOT have any error - spec.* fields don't need Required
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "status dependency") {
			t.Errorf("Should not error about status dependency for spec.* fields, got: %s", e.Message)
		}
	}
}
