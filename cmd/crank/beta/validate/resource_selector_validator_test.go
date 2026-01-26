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
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestResourceSelectorValidator_DetectAmbiguousSelectors(t *testing.T) {
	// Simulate StampNetworkingV2 creating subnets with generic labels
	networkingComp := &ParsedComposition{
		Name: "stampnetworking-v2-aws",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "px.physicsx.ai",
			Version: "v1alpha1",
			Kind:    "StampNetworkingV2",
		},
		Resources: []ComposedResource{
			{
				Name: "subnet-private-1",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "ec2.aws.upbound.io/v1beta1",
						"kind":       "Subnet",
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{
								"type":       "subnet",
								"visibility": "private",
								"zone":       "1",
							},
						},
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{},
						},
					},
				},
			},
			{
				Name: "subnet-private-2",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "ec2.aws.upbound.io/v1beta1",
						"kind":       "Subnet",
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{
								"type":       "subnet",
								"visibility": "private",
								"zone":       "2",
							},
						},
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{},
						},
					},
				},
			},
		},
		SourceFile: "StampNetworkingV2/composition-aws.yaml",
	}

	// Simulate StampClusterV2 selecting subnets with generic labels (NO matchControllerRef)
	clusterComp := &ParsedComposition{
		Name: "stampcluster-v2-aws",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "px.physicsx.ai",
			Version: "v1alpha1",
			Kind:    "StampClusterV2",
		},
		Resources: []ComposedResource{
			{
				Name: "eks-cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "eks.aws.upbound.io/v1beta2",
						"kind":       "Cluster",
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{
								"vpcConfig": map[string]interface{}{
									"subnetIdSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{
											"type":       "subnet",
											"visibility": "private",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		SourceFile: "StampClusterV2/composition-aws.yaml",
	}

	compositions := []*ParsedComposition{networkingComp, clusterComp}
	validator := NewResourceSelectorValidator(compositions)

	errors := validator.Validate()

	// Should detect the ambiguous selector
	if len(errors) == 0 {
		t.Errorf("Expected at least 1 error for ambiguous selector, got 0")
	}

	found := false
	for _, err := range errors {
		if err.CompositionName == "stampcluster-v2-aws" &&
			err.ResourceName == "eks-cluster" &&
			err.SelectorPath == "spec.forProvider.vpcConfig.subnetIdSelector" {
			found = true
			if err.Severity != "warning" {
				t.Errorf("Expected severity 'warning', got %s", err.Severity)
			}
			// Should mention stampnetworking
			if len(err.Creators) == 0 {
				t.Errorf("Expected creators to be populated")
			}
		}
	}

	if !found {
		t.Errorf("Expected to find error for eks-cluster subnetIdSelector, got errors: %+v", errors)
	}
}

func TestResourceSelectorValidator_MatchControllerRefSkipsWarning(t *testing.T) {
	// Composition that creates subnets with labels (both public and private)
	networkingComp := &ParsedComposition{
		Name: "stampnetworking-v2-aws",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "px.physicsx.ai",
			Version: "v1alpha1",
			Kind:    "StampNetworkingV2",
		},
		Resources: []ComposedResource{
			{
				Name: "subnet-private",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "ec2.aws.upbound.io/v1beta1",
						"kind":       "Subnet",
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{
								"type":       "subnet",
								"visibility": "private",
							},
						},
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{},
						},
					},
				},
			},
			{
				Name: "subnet-public",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "ec2.aws.upbound.io/v1beta1",
						"kind":       "Subnet",
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{
								"type":       "subnet",
								"visibility": "public",
							},
						},
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{},
						},
					},
				},
			},
			{
				// NAT Gateway in SAME composition selects subnet with matchControllerRef
				Name: "nat-gateway",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "ec2.aws.upbound.io/v1beta1",
						"kind":       "NATGateway",
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{
								"subnetIdSelector": map[string]interface{}{
									"matchControllerRef": true,
									"matchLabels": map[string]interface{}{
										"type":       "subnet",
										"visibility": "public",
									},
								},
							},
						},
					},
				},
			},
		},
		SourceFile: "StampNetworkingV2/composition-aws.yaml",
	}

	compositions := []*ParsedComposition{networkingComp}
	validator := NewResourceSelectorValidator(compositions)

	errors := validator.Validate()

	// Should NOT detect any ambiguity errors because matchControllerRef is used
	for _, err := range errors {
		if err.ResourceName == "nat-gateway" && strings.Contains(err.Message, "ambiguous") {
			t.Errorf("Expected no ambiguity errors for nat-gateway with matchControllerRef, got: %s", err.Message)
		}
	}
}

func TestResourceSelectorValidator_OrphanedSelector(t *testing.T) {
	// Composition that uses a selector with labels that don't exist anywhere
	clusterComp := &ParsedComposition{
		Name: "test-composition",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "px.physicsx.ai",
			Version: "v1alpha1",
			Kind:    "TestXR",
		},
		Resources: []ComposedResource{
			{
				Name: "test-resource",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "ec2.aws.upbound.io/v1beta1",
						"kind":       "SomeResource",
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{
								"subnetIdSelector": map[string]interface{}{
									"matchLabels": map[string]interface{}{
										"nonexistent": "label",
										"another":     "missing",
									},
								},
							},
						},
					},
				},
			},
		},
		SourceFile: "test/composition.yaml",
	}

	compositions := []*ParsedComposition{clusterComp}
	validator := NewResourceSelectorValidator(compositions)

	errors := validator.Validate()

	// Should detect orphaned selector
	found := false
	for _, err := range errors {
		if err.Message == "selector uses labels that are not created by any composition" {
			found = true
		}
	}

	if !found {
		t.Errorf("Expected to find orphaned selector error, got: %+v", errors)
	}
}

func TestResourceSelectorValidator_UniqueIdentifierSkipsWarning(t *testing.T) {
	// Networking creates subnets with stamp-name label
	networkingComp := &ParsedComposition{
		Name: "stampnetworking-v2-aws",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "px.physicsx.ai",
			Version: "v1alpha1",
			Kind:    "StampNetworkingV2",
		},
		Resources: []ComposedResource{
			{
				Name: "subnet-private",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "ec2.aws.upbound.io/v1beta1",
						"kind":       "Subnet",
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{
								"type":       "subnet",
								"visibility": "private",
								"stamp-name": "",
							},
						},
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{},
						},
					},
				},
			},
		},
		SourceFile: "StampNetworkingV2/composition-aws.yaml",
	}

	// Cluster selects with stamp-name label (unique identifier)
	clusterComp := &ParsedComposition{
		Name: "stampcluster-v2-aws",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "px.physicsx.ai",
			Version: "v1alpha1",
			Kind:    "StampClusterV2",
		},
		Resources: []ComposedResource{
			{
				Name: "eks-cluster",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "eks.aws.upbound.io/v1beta2",
						"kind":       "Cluster",
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{
								"vpcConfig": map[string]interface{}{
									"subnetIdSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{
											"type":       "subnet",
											"visibility": "private",
											"stamp-name": "",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		SourceFile: "StampClusterV2/composition-aws.yaml",
	}

	compositions := []*ParsedComposition{networkingComp, clusterComp}
	validator := NewResourceSelectorValidator(compositions)

	errors := validator.Validate()

	// Should NOT detect ambiguous selector because stamp-name is a unique identifier
	for _, err := range errors {
		if err.ResourceName == "eks-cluster" && err.Severity == "warning" &&
			!strings.Contains(err.Message, "orphan") {
			t.Errorf("Expected no ambiguous selector warning for eks-cluster with stamp-name, got: %s", err.Message)
		}
	}
}

func TestResourceSelectorValidator_ExtractLabels(t *testing.T) {
	comp := &ParsedComposition{
		Name: "test-comp",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "test.io",
			Version: "v1",
			Kind:    "TestXR",
		},
		Resources: []ComposedResource{
			{
				Name: "test-resource",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "test.io/v1",
						"kind":       "TestResource",
						"metadata": map[string]interface{}{
							"labels": map[string]interface{}{
								"key1": "value1",
								"key2": "value2",
							},
						},
					},
				},
			},
		},
	}

	validator := NewResourceSelectorValidator([]*ParsedComposition{comp})
	creators := validator.GetLabelCreators()

	// Should have one label set
	if len(creators) != 1 {
		t.Errorf("Expected 1 label set, got %d", len(creators))
	}

	// Check the creators
	for key, infos := range creators {
		if len(infos) != 1 {
			t.Errorf("Expected 1 creator for key %s, got %d", key, len(infos))
		}
		if infos[0].CompositionName != "test-comp" {
			t.Errorf("Expected composition name 'test-comp', got %s", infos[0].CompositionName)
		}
	}
}

func TestResourceSelectorValidator_ExtractSelectors(t *testing.T) {
	comp := &ParsedComposition{
		Name: "test-comp",
		CompositeTypeRef: schema.GroupVersionKind{
			Group:   "test.io",
			Version: "v1",
			Kind:    "TestXR",
		},
		Resources: []ComposedResource{
			{
				Name: "test-resource",
				Base: &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "test.io/v1",
						"kind":       "TestResource",
						"spec": map[string]interface{}{
							"forProvider": map[string]interface{}{
								"subnetIdSelector": map[string]interface{}{
									"matchLabels": map[string]interface{}{
										"type": "subnet",
									},
								},
								"vpcConfig": map[string]interface{}{
									"securityGroupIdSelector": map[string]interface{}{
										"matchControllerRef": true,
										"matchLabels": map[string]interface{}{
											"role": "cluster",
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

	validator := NewResourceSelectorValidator([]*ParsedComposition{comp})
	selectors := validator.GetSelectors()

	// Should have two selectors
	if len(selectors) != 2 {
		t.Errorf("Expected 2 selectors, got %d", len(selectors))
		for _, s := range selectors {
			t.Logf("  Found: %s", s.SelectorPath)
		}
	}

	// Check that matchControllerRef is detected
	foundWithRef := false
	foundWithoutRef := false
	for _, s := range selectors {
		if s.HasControllerRef {
			foundWithRef = true
		} else {
			foundWithoutRef = true
		}
	}

	if !foundWithRef {
		t.Errorf("Expected to find selector with matchControllerRef")
	}
	if !foundWithoutRef {
		t.Errorf("Expected to find selector without matchControllerRef")
	}
}

func TestExtractLabelKey(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "bracket notation",
			path:     `metadata.labels["stamp-name"]`,
			expected: "stamp-name",
		},
		{
			name:     "dot notation",
			path:     "metadata.labels.stamp-name",
			expected: "stamp-name",
		},
		{
			name:     "nested bracket",
			path:     `spec.forProvider.tags["my-key"]`,
			expected: "my-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLabelKey(tt.path)
			if result != tt.expected {
				t.Errorf("extractLabelKey(%s) = %s, want %s", tt.path, result, tt.expected)
			}
		})
	}
}

func TestLabelsSubset(t *testing.T) {
	tests := []struct {
		name     string
		subset   map[string]string
		superset map[string]string
		expected bool
	}{
		{
			name:     "exact match",
			subset:   map[string]string{"a": "1", "b": "2"},
			superset: map[string]string{"a": "1", "b": "2"},
			expected: true,
		},
		{
			name:     "proper subset",
			subset:   map[string]string{"a": "1"},
			superset: map[string]string{"a": "1", "b": "2"},
			expected: true,
		},
		{
			name:     "value mismatch",
			subset:   map[string]string{"a": "1"},
			superset: map[string]string{"a": "2"},
			expected: false,
		},
		{
			name:     "key missing",
			subset:   map[string]string{"c": "3"},
			superset: map[string]string{"a": "1", "b": "2"},
			expected: false,
		},
		{
			name:     "empty subset",
			subset:   map[string]string{},
			superset: map[string]string{"a": "1"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := labelsSubset(tt.subset, tt.superset)
			if result != tt.expected {
				t.Errorf("labelsSubset(%v, %v) = %v, want %v", tt.subset, tt.superset, result, tt.expected)
			}
		})
	}
}

func TestSerializeLabels(t *testing.T) {
	labels := map[string]string{
		"b": "2",
		"a": "1",
		"c": "3",
	}

	result := serializeLabels(labels)
	expected := "a=1,b=2,c=3"

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("serializeLabels() mismatch (-want +got):\n%s", diff)
	}
}

