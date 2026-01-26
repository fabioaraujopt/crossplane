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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestTagValidator_MissingTagManager(t *testing.T) {
	// Composition that creates AWS resources WITHOUT tag-manager
	compositionWithoutTagManager := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "TestComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "s3-bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
								},
							},
						},
					},
					// NO tag-manager step!
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{})
	result := validator.Validate([]*unstructured.Unstructured{compositionWithoutTagManager})

	assert.Equal(t, 1, result.CloudCompositions, "Should detect 1 composition with cloud resources")
	assert.Equal(t, 1, result.MissingTagManager, "Should detect missing tag-manager")
	require.Len(t, result.Warnings, 1, "Should have 1 warning")
	assert.Equal(t, "missing-tag-manager", result.Warnings[0].Rule)
	assert.Contains(t, result.Warnings[0].Affected, "s3.aws.upbound.io/v1beta1/Bucket")
}

func TestTagValidator_WithTagManager(t *testing.T) {
	// Composition that creates AWS resources WITH tag-manager
	compositionWithTagManager := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-composition-with-tags",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "TestComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "s3-bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
								},
							},
						},
					},
					map[string]interface{}{
						"step": "manage-tags",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-tag-manager",
						},
						"input": map[string]interface{}{
							"apiVersion": "tag-manager.fn.crossplane.io/v1beta1",
							"kind":       "ManagedTags",
							"addTags": []interface{}{
								map[string]interface{}{
									"type": "FromValue",
									"tags": map[string]interface{}{
										"ManagedBy":    "Crossplane",
										"StampVersion": "v1",
									},
								},
								map[string]interface{}{
									"type":          "FromCompositeFieldPath",
									"fromFieldPath": "spec.parameters.tags",
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{})
	result := validator.Validate([]*unstructured.Unstructured{compositionWithTagManager})

	assert.Equal(t, 1, result.CloudCompositions, "Should detect 1 composition with cloud resources")
	assert.Equal(t, 0, result.MissingTagManager, "Should not detect missing tag-manager")
}

func TestTagValidator_MissingRequiredTags(t *testing.T) {
	// Composition with tag-manager but missing required tags
	compositionMissingTags := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "test-composition-missing-tags",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "TestComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "rds-cluster",
									"base": map[string]interface{}{
										"apiVersion": "rds.aws.upbound.io/v1beta1",
										"kind":       "Cluster",
									},
								},
							},
						},
					},
					map[string]interface{}{
						"step": "manage-tags",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-tag-manager",
						},
						"input": map[string]interface{}{
							"apiVersion": "tag-manager.fn.crossplane.io/v1beta1",
							"kind":       "ManagedTags",
							"addTags": []interface{}{
								map[string]interface{}{
									"type": "FromValue",
									"tags": map[string]interface{}{
										"ManagedBy": "Crossplane",
										// Missing StampName, Environment
									},
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{
		RequiredTags: []string{"ManagedBy", "StampName", "Environment"},
	})
	result := validator.Validate([]*unstructured.Unstructured{compositionMissingTags})

	assert.Equal(t, 1, result.CloudCompositions)
	assert.Equal(t, 0, result.MissingTagManager)

	// Should warn about missing required tags
	hasTagWarning := false
	for _, w := range result.Warnings {
		if w.Rule == "missing-required-tags" {
			hasTagWarning = true
			assert.Contains(t, w.Message, "StampName")
			assert.Contains(t, w.Message, "Environment")
		}
	}
	assert.True(t, hasTagWarning, "Should have warning about missing required tags")
}

func TestTagValidator_TagsNotPropagated(t *testing.T) {
	// Parent composition that doesn't pass tags to child
	parentComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "parent-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "ParentComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "child-resource",
									"base": map[string]interface{}{
										"apiVersion": "cloud.example.com/v1alpha1",
										"kind":       "ChildComposite",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.parameters.region",
										},
										// Missing tags patch!
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Child composition that expects tags
	childComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "child-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "ChildComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "s3-bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
								},
							},
						},
					},
					map[string]interface{}{
						"step": "manage-tags",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-tag-manager",
						},
						"input": map[string]interface{}{
							"apiVersion": "tag-manager.fn.crossplane.io/v1beta1",
							"kind":       "ManagedTags",
							"addTags": []interface{}{
								map[string]interface{}{
									"type": "FromValue",
									"tags": map[string]interface{}{
										"ManagedBy": "Crossplane",
									},
								},
								map[string]interface{}{
									"type":          "FromCompositeFieldPath",
									"fromFieldPath": "spec.parameters.tags", // Expects tags from parent!
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{})
	result := validator.Validate([]*unstructured.Unstructured{parentComposition, childComposition})

	// Should warn about tags not being propagated
	hasPropagationWarning := false
	for _, w := range result.Warnings {
		if w.Rule == "tags-not-propagated" {
			hasPropagationWarning = true
			assert.Contains(t, w.Message, "ChildComposite")
		}
	}
	assert.True(t, hasPropagationWarning, "Should have warning about tags not propagated")
}

func TestTagValidator_TagsPropagatedCorrectly(t *testing.T) {
	// Parent composition that correctly passes tags to child
	parentComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "parent-composition-correct",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "ParentComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "child-resource",
									"base": map[string]interface{}{
										"apiVersion": "cloud.example.com/v1alpha1",
										"kind":       "ChildComposite",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.region",
											"toFieldPath":   "spec.parameters.region",
										},
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.tags",
											"toFieldPath":   "spec.parameters.tags", // Tags passed correctly!
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

	// Child composition that expects tags
	childComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "child-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "ChildComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "s3-bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
								},
							},
						},
					},
					map[string]interface{}{
						"step": "manage-tags",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-tag-manager",
						},
						"input": map[string]interface{}{
							"apiVersion": "tag-manager.fn.crossplane.io/v1beta1",
							"kind":       "ManagedTags",
							"addTags": []interface{}{
								map[string]interface{}{
									"type":          "FromCompositeFieldPath",
									"fromFieldPath": "spec.parameters.tags",
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{})
	result := validator.Validate([]*unstructured.Unstructured{parentComposition, childComposition})

	// Should NOT warn about tags not being propagated
	hasPropagationWarning := false
	for _, w := range result.Warnings {
		if w.Rule == "tags-not-propagated" {
			hasPropagationWarning = true
		}
	}
	assert.False(t, hasPropagationWarning, "Should not have warning about tags propagation when correct")
}

func TestTagValidator_AzureResources(t *testing.T) {
	// Composition that creates Azure resources without tag-manager
	azureComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "azure-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "AzureComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "storage-account",
									"base": map[string]interface{}{
										"apiVersion": "storage.azure.upbound.io/v1beta1",
										"kind":       "Account",
									},
								},
								map[string]interface{}{
									"name": "redis-cache",
									"base": map[string]interface{}{
										"apiVersion": "cache.azure.upbound.io/v1beta1",
										"kind":       "RedisCache",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{})
	result := validator.Validate([]*unstructured.Unstructured{azureComposition})

	assert.Equal(t, 1, result.CloudCompositions)
	assert.Equal(t, 1, result.MissingTagManager)
	require.Len(t, result.Warnings, 1)
	assert.Equal(t, "missing-tag-manager", result.Warnings[0].Rule)
	assert.Len(t, result.Warnings[0].Affected, 2) // Both Azure resources
}

func TestTagValidator_NonCloudResources(t *testing.T) {
	// Composition that creates only Kubernetes resources (no cloud)
	k8sComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "k8s-only-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "K8sComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "namespace",
									"base": map[string]interface{}{
										"apiVersion": "kubernetes.crossplane.io/v1alpha2",
										"kind":       "Object",
									},
								},
								map[string]interface{}{
									"name": "helm-release",
									"base": map[string]interface{}{
										"apiVersion": "helm.crossplane.io/v1beta1",
										"kind":       "Release",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{})
	result := validator.Validate([]*unstructured.Unstructured{k8sComposition})

	assert.Equal(t, 0, result.CloudCompositions, "Should not count K8s-only compositions as cloud")
	assert.Equal(t, 0, result.MissingTagManager)
	assert.Len(t, result.Warnings, 0)
}

func TestTagValidator_SkipComposition(t *testing.T) {
	composition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "skip-this-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "SkipComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "s3-bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{
		SkipCompositions: []string{"skip-this-composition"},
	})
	result := validator.Validate([]*unstructured.Unstructured{composition})

	assert.Equal(t, 0, result.CloudCompositions, "Should skip composition")
	assert.Len(t, result.Warnings, 0)
}

func TestTagValidator_BuildTagPropagationTree(t *testing.T) {
	// Root composition
	rootComposition := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "root-composition",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "RootComposite",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "child-1",
									"base": map[string]interface{}{
										"apiVersion": "cloud.example.com/v1alpha1",
										"kind":       "ChildComposite1",
									},
									"patches": []interface{}{
										map[string]interface{}{
											"fromFieldPath": "spec.parameters.tags",
											"toFieldPath":   "spec.parameters.tags",
										},
									},
								},
								map[string]interface{}{
									"name": "child-2",
									"base": map[string]interface{}{
										"apiVersion": "cloud.example.com/v1alpha1",
										"kind":       "ChildComposite2",
									},
									// No tags patch!
								},
							},
						},
					},
					map[string]interface{}{
						"step": "manage-tags",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-tag-manager",
						},
						"input": map[string]interface{}{
							"apiVersion": "tag-manager.fn.crossplane.io/v1beta1",
							"kind":       "ManagedTags",
							"addTags": []interface{}{
								map[string]interface{}{
									"type": "FromValue",
									"tags": map[string]interface{}{
										"ManagedBy": "Crossplane",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Child composition 1 (creates cloud resources, expects tags)
	childComposition1 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "child-composition-1",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "ChildComposite1",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "s3-bucket",
									"base": map[string]interface{}{
										"apiVersion": "s3.aws.upbound.io/v1beta1",
										"kind":       "Bucket",
									},
								},
							},
						},
					},
					map[string]interface{}{
						"step": "manage-tags",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-tag-manager",
						},
						"input": map[string]interface{}{
							"apiVersion": "tag-manager.fn.crossplane.io/v1beta1",
							"kind":       "ManagedTags",
							"addTags": []interface{}{
								map[string]interface{}{
									"type":          "FromCompositeFieldPath",
									"fromFieldPath": "spec.parameters.tags",
								},
							},
						},
					},
				},
			},
		},
	}

	// Child composition 2 (creates cloud resources, expects tags)
	childComposition2 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.crossplane.io/v2",
			"kind":       "Composition",
			"metadata": map[string]interface{}{
				"name": "child-composition-2",
			},
			"spec": map[string]interface{}{
				"compositeTypeRef": map[string]interface{}{
					"apiVersion": "cloud.example.com/v1alpha1",
					"kind":       "ChildComposite2",
				},
				"mode": "Pipeline",
				"pipeline": []interface{}{
					map[string]interface{}{
						"step": "render",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-patch-and-transform",
						},
						"input": map[string]interface{}{
							"apiVersion": "pt.fn.crossplane.io/v1beta1",
							"kind":       "Resources",
							"resources": []interface{}{
								map[string]interface{}{
									"name": "rds-cluster",
									"base": map[string]interface{}{
										"apiVersion": "rds.aws.upbound.io/v1beta1",
										"kind":       "Cluster",
									},
								},
							},
						},
					},
					map[string]interface{}{
						"step": "manage-tags",
						"functionRef": map[string]interface{}{
							"name": "crossplane-function-tag-manager",
						},
						"input": map[string]interface{}{
							"apiVersion": "tag-manager.fn.crossplane.io/v1beta1",
							"kind":       "ManagedTags",
							"addTags": []interface{}{
								map[string]interface{}{
									"type":          "FromCompositeFieldPath",
									"fromFieldPath": "spec.parameters.tags",
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewTagValidator(TagValidatorConfig{})
	tree := validator.BuildTagPropagationTree(
		[]*unstructured.Unstructured{rootComposition, childComposition1, childComposition2},
		"RootComposite",
	)

	require.NotNil(t, tree)
	assert.Equal(t, "RootComposite", tree.Kind)
	assert.True(t, tree.HasTagManager)
	assert.Len(t, tree.Children, 2)

	// Print tree for visual verification
	treeStr := validator.PrintTagPropagationTree(tree, "", false)
	t.Logf("Tag Propagation Tree:\n%s", treeStr)

	assert.Contains(t, treeStr, "RootComposite")
	assert.Contains(t, treeStr, "ChildComposite1")
	assert.Contains(t, treeStr, "ChildComposite2")
}
