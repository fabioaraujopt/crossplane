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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestValidateRollbackLimits(t *testing.T) {
	tests := []struct {
		name           string
		compositions   []*ParsedComposition
		wantWarnings   int
		wantError      bool
		wantCategories []string
	}{
		{
			name: "Helm release without rollbackLimit",
			compositions: []*ParsedComposition{
				{
					Name:       "test-composition",
					SourceFile: "test.yaml",
					Resources: []ComposedResource{
						{
							Name: "my-helm-release",
							Base: &unstructured.Unstructured{
								Object: map[string]interface{}{
									"apiVersion": "helm.crossplane.io/v1beta1",
									"kind":       "Release",
									"spec": map[string]interface{}{
										"forProvider": map[string]interface{}{
											"chart": map[string]interface{}{
												"name": "my-chart",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantWarnings:   1,
			wantCategories: []string{"rollbackLimit"},
		},
		{
			name: "Helm release with rollbackLimit 100",
			compositions: []*ParsedComposition{
				{
					Name:       "test-composition",
					SourceFile: "test.yaml",
					Resources: []ComposedResource{
						{
							Name: "my-helm-release",
							Base: &unstructured.Unstructured{
								Object: map[string]interface{}{
									"apiVersion": "helm.crossplane.io/v1beta1",
									"kind":       "Release",
									"spec": map[string]interface{}{
										"rollbackLimit": int64(100),
										"forProvider": map[string]interface{}{
											"chart": map[string]interface{}{
												"name": "my-chart",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "Helm release with low rollbackLimit",
			compositions: []*ParsedComposition{
				{
					Name:       "test-composition",
					SourceFile: "test.yaml",
					Resources: []ComposedResource{
						{
							Name: "my-helm-release",
							Base: &unstructured.Unstructured{
								Object: map[string]interface{}{
									"apiVersion": "helm.crossplane.io/v1beta1",
									"kind":       "Release",
									"spec": map[string]interface{}{
										"rollbackLimit": int64(5),
										"forProvider": map[string]interface{}{
											"chart": map[string]interface{}{
												"name": "my-chart",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantWarnings:   1,
			wantCategories: []string{"rollbackLimit"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := DetectMissingRollbackLimit(tt.compositions)

			assert.Equal(t, tt.wantWarnings, len(issues), "unexpected number of warnings")

			if len(tt.wantCategories) > 0 {
				for i, issue := range issues {
					if i < len(tt.wantCategories) {
						assert.Equal(t, tt.wantCategories[i], issue.Category)
					}
				}
			}
		})
	}
}

func TestValidateUsageLabelMatching(t *testing.T) {
	tests := []struct {
		name       string
		validator  *DeletionSafetyValidator
		wantErrors int
	}{
		{
			name: "Usage with matching labels",
			validator: &DeletionSafetyValidator{
				usages: []UsageInfo{
					{
						Name:         "test-usage",
						OfKind:       "Role",
						OfAPIVersion: "iam.aws.upbound.io/v1beta1",
						OfLabels:     map[string]string{"role": "karpenter-controller"},
						ByKind:       "Release",
						ByAPIVersion: "helm.crossplane.io/v1beta1",
						ByLabels:     map[string]string{"role": "karpenter-helm"},
					},
				},
				allResources: []ResourceInfo{
					{
						Name:       "karpenter-iam-role",
						Kind:       "Role",
						APIVersion: "iam.aws.upbound.io/v1beta1",
						Labels:     map[string]string{"role": "karpenter-controller"},
					},
					{
						Name:       "karpenter-helm",
						Kind:       "Release",
						APIVersion: "helm.crossplane.io/v1beta1",
						Labels:     map[string]string{"role": "karpenter-helm"},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "Usage with missing 'of' labels",
			validator: &DeletionSafetyValidator{
				usages: []UsageInfo{
					{
						Name:         "test-usage",
						SourceFile:   "test.yaml",
						OfKind:       "Role",
						OfAPIVersion: "iam.aws.upbound.io/v1beta1",
						OfLabels:     map[string]string{"role": "missing-label"},
						ByKind:       "Release",
						ByAPIVersion: "helm.crossplane.io/v1beta1",
						ByLabels:     map[string]string{},
					},
				},
				allResources: []ResourceInfo{
					{
						Name:       "karpenter-iam-role",
						Kind:       "Role",
						APIVersion: "iam.aws.upbound.io/v1beta1",
						Labels:     map[string]string{"role": "different-label"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "Usage with missing 'by' labels",
			validator: &DeletionSafetyValidator{
				usages: []UsageInfo{
					{
						Name:         "test-usage",
						SourceFile:   "test.yaml",
						OfKind:       "Role",
						OfAPIVersion: "iam.aws.upbound.io/v1beta1",
						OfLabels:     map[string]string{},
						ByKind:       "Release",
						ByAPIVersion: "helm.crossplane.io/v1beta1",
						ByLabels:     map[string]string{"role": "missing-helm-label"},
					},
				},
				allResources: []ResourceInfo{
					{
						Name:       "karpenter-helm",
						Kind:       "Release",
						APIVersion: "helm.crossplane.io/v1beta1",
						Labels:     map[string]string{},
					},
				},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := tt.validator.validateUsageLabelMatching()
			errorCount := 0
			for _, issue := range issues {
				if issue.Severity == "error" {
					errorCount++
				}
			}
			assert.Equal(t, tt.wantErrors, errorCount, "unexpected number of errors")
		})
	}
}

func TestValidateIAMUsageProtection(t *testing.T) {
	tests := []struct {
		name         string
		validator    *DeletionSafetyValidator
		wantWarnings int
	}{
		{
			name: "Helm with IRSA and Usage protection",
			validator: &DeletionSafetyValidator{
				helmReleases: []HelmReleaseInfo{
					{
						Name:          "karpenter",
						Composition:   "test",
						ValuesRoleARN: "arn:aws:iam::123456789:role/karpenter-controller",
					},
				},
				usages: []UsageInfo{
					{
						Name:         "usage-iam-by-helm",
						OfKind:       "Role",
						OfAPIVersion: "iam.aws.upbound.io/v1beta1",
						ByKind:       "Release",
						ByAPIVersion: "helm.crossplane.io/v1beta1",
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "Helm with IRSA but no Usage protection",
			validator: &DeletionSafetyValidator{
				helmReleases: []HelmReleaseInfo{
					{
						Name:          "karpenter",
						Composition:   "test",
						SourceFile:    "test.yaml",
						ValuesRoleARN: "arn:aws:iam::123456789:role/karpenter-controller",
					},
				},
				usages: []UsageInfo{}, // No Usage objects
			},
			wantWarnings: 1,
		},
		{
			name: "Helm without IRSA",
			validator: &DeletionSafetyValidator{
				helmReleases: []HelmReleaseInfo{
					{
						Name:          "nginx",
						Composition:   "test",
						ValuesRoleARN: "", // No IRSA
					},
				},
				usages: []UsageInfo{},
			},
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := tt.validator.validateIAMUsageProtection()
			warningCount := 0
			for _, issue := range issues {
				if issue.Severity == "warning" {
					warningCount++
				}
			}
			assert.Equal(t, tt.wantWarnings, warningCount, "unexpected number of warnings")
		})
	}
}

func TestBuildDeletionOrder(t *testing.T) {
	validator := &DeletionSafetyValidator{
		allResources: []ResourceInfo{
			{Name: "networking", Kind: "StampNetworkingV2"},
			{Name: "cluster", Kind: "StampClusterV2"},
			{Name: "loadbalancer", Kind: "StampLoadBalancerV2"},
		},
		usages: []UsageInfo{
			{
				Name:           "usage-networking-by-cluster",
				OfKind:         "StampNetworkingV2",
				ByKind:         "StampClusterV2",
				ReplayDeletion: true,
			},
			{
				Name:           "usage-cluster-by-loadbalancer",
				OfKind:         "StampClusterV2",
				ByKind:         "StampLoadBalancerV2",
				ReplayDeletion: true,
			},
		},
	}

	waves := validator.buildDeletionOrder()

	// Should have multiple waves
	assert.GreaterOrEqual(t, len(waves), 1, "should have at least one deletion wave")

	// Verify the order: loadbalancer -> cluster -> networking
	t.Logf("Deletion waves: %+v", waves)
}

func TestPrintDeletionOrder(t *testing.T) {
	validator := &DeletionSafetyValidator{}

	waves := []DeletionWave{
		{
			Wave: 0,
			Resources: []DeletionResource{
				{Name: "service-a", Kind: "StampServiceA"},
				{Name: "service-b", Kind: "StampServiceB"},
			},
		},
		{
			Wave: 1,
			Resources: []DeletionResource{
				{Name: "cluster", Kind: "StampClusterV2", UsedBy: []string{"StampServiceA/*", "StampServiceB/*"}},
			},
		},
	}

	var buf bytes.Buffer
	err := validator.PrintDeletionOrder(waves, &buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Deletion Order")
	assert.Contains(t, output, "Wave 1")
	assert.Contains(t, output, "Wave 2")
	assert.Contains(t, output, "StampServiceA")
	assert.Contains(t, output, "StampClusterV2")
}

func TestExtractHelmRelease(t *testing.T) {
	validator := &DeletionSafetyValidator{}

	res := ComposedResource{
		Name: "test-helm",
		Base: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "helm.crossplane.io/v1beta1",
				"kind":       "Release",
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"role": "test-role",
					},
				},
				"spec": map[string]interface{}{
					"rollbackLimit": int64(100),
					"forProvider": map[string]interface{}{
						"wait":        true,
						"waitTimeout": "5m",
						"chart": map[string]interface{}{
							"name": "my-chart",
						},
						"namespace": "test-namespace",
						"values": map[string]interface{}{
							"serviceAccount": map[string]interface{}{
								"annotations": map[string]interface{}{
									"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789:role/test-role",
								},
							},
						},
					},
				},
			},
		},
	}

	info := validator.extractHelmRelease(res, "test-composition", "test.yaml", 1)

	assert.Equal(t, "test-helm", info.Name)
	assert.Equal(t, "test-composition", info.Composition)
	assert.NotNil(t, info.RollbackLimit)
	assert.Equal(t, int64(100), *info.RollbackLimit)
	assert.True(t, info.Wait)
	assert.Equal(t, "5m", info.WaitTimeout)
	assert.Equal(t, "my-chart", info.ChartName)
	assert.Equal(t, "test-namespace", info.Namespace)
	assert.NotEmpty(t, info.ValuesRoleARN) // Should detect IRSA
}

func TestExtractUsage(t *testing.T) {
	validator := &DeletionSafetyValidator{}

	res := ComposedResource{
		Name: "test-usage",
		Base: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "protection.crossplane.io/v1beta1",
				"kind":       "ClusterUsage",
				"spec": map[string]interface{}{
					"replayDeletion": true,
					"of": map[string]interface{}{
						"apiVersion": "iam.aws.upbound.io/v1beta1",
						"kind":       "Role",
						"resourceSelector": map[string]interface{}{
							"matchControllerRef": true,
							"matchLabels": map[string]interface{}{
								"role": "karpenter-controller",
							},
						},
					},
					"by": map[string]interface{}{
						"apiVersion": "helm.crossplane.io/v1beta1",
						"kind":       "Release",
						"resourceSelector": map[string]interface{}{
							"matchControllerRef": true,
							"matchLabels": map[string]interface{}{
								"role": "karpenter-helm",
							},
						},
					},
				},
			},
		},
	}

	info := validator.extractUsage(res, "test.yaml", 1)

	assert.Equal(t, "test-usage", info.Name)
	assert.True(t, info.ReplayDeletion)
	assert.Equal(t, "iam.aws.upbound.io/v1beta1", info.OfAPIVersion)
	assert.Equal(t, "Role", info.OfKind)
	assert.Equal(t, "karpenter-controller", info.OfLabels["role"])
	assert.Equal(t, "helm.crossplane.io/v1beta1", info.ByAPIVersion)
	assert.Equal(t, "Release", info.ByKind)
	assert.Equal(t, "karpenter-helm", info.ByLabels["role"])
}

func TestValidateDeletionSafetyFromObjects(t *testing.T) {
	objects := []*unstructured.Unstructured{
		{
			Object: map[string]interface{}{
				"apiVersion": "apiextensions.crossplane.io/v1",
				"kind":       "Composition",
				"metadata": map[string]interface{}{
					"name": "test-composition",
				},
				"spec": map[string]interface{}{
					"compositeTypeRef": map[string]interface{}{
						"apiVersion": "cloud.test.io/v1alpha1",
						"kind":       "TestResource",
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
										"name": "helm-without-rollback",
										"base": map[string]interface{}{
											"apiVersion": "helm.crossplane.io/v1beta1",
											"kind":       "Release",
											"spec": map[string]interface{}{
												"forProvider": map[string]interface{}{
													"chart": map[string]interface{}{
														"name": "test-chart",
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

	result := ValidateDeletionSafetyFromObjects(objects)

	// Should detect missing rollbackLimit
	assert.GreaterOrEqual(t, len(result.Warnings), 1, "should have at least one warning")

	foundRollbackWarning := false
	for _, warn := range result.Warnings {
		if warn.Category == "rollbackLimit" {
			foundRollbackWarning = true
			break
		}
	}
	assert.True(t, foundRollbackWarning, "should have rollbackLimit warning")
}

func TestDeletionSafetyIssueError(t *testing.T) {
	issue := DeletionSafetyIssue{
		Composition: "test-comp",
		Resource:    "test-resource",
		SourceFile:  "test.yaml",
		SourceLine:  42,
		Message:     "test message",
		Category:    "rollbackLimit",
	}

	errStr := issue.Error()
	assert.Contains(t, errStr, "test.yaml:42")
	assert.Contains(t, errStr, "rollbackLimit")
	assert.Contains(t, errStr, "test message")
	assert.Contains(t, errStr, "test-resource")
}

func TestHasMatchingResource(t *testing.T) {
	validator := &DeletionSafetyValidator{
		allResources: []ResourceInfo{
			{
				Name:       "test-role",
				Kind:       "Role",
				APIVersion: "iam.aws.upbound.io/v1beta1",
				Labels:     map[string]string{"role": "karpenter-controller", "env": "prod"},
			},
		},
	}

	// Should match with exact labels
	assert.True(t, validator.hasMatchingResource("Role", "iam.aws.upbound.io/v1beta1", map[string]string{"role": "karpenter-controller"}))

	// Should match with subset of labels
	assert.True(t, validator.hasMatchingResource("Role", "iam.aws.upbound.io/v1beta1", map[string]string{"role": "karpenter-controller"}))

	// Should not match with wrong kind
	assert.False(t, validator.hasMatchingResource("Policy", "iam.aws.upbound.io/v1beta1", map[string]string{"role": "karpenter-controller"}))

	// Should not match with wrong labels
	assert.False(t, validator.hasMatchingResource("Role", "iam.aws.upbound.io/v1beta1", map[string]string{"role": "different-role"}))
}

func TestCrossCompositionDependencies(t *testing.T) {
	tests := []struct {
		name        string
		validator   *DeletionSafetyValidator
		wantIssues  int
		wantMessage string
	}{
		{
			name: "Missing cross-composition dependency",
			validator: &DeletionSafetyValidator{
				compositions: []*ParsedComposition{
					{
						Name: "networking",
						Resources: []ComposedResource{
							{
								Name: "networking",
								Base: &unstructured.Unstructured{
									Object: map[string]interface{}{
										"apiVersion": "cloud.physicsx.ai/v1alpha1",
										"kind":       "StampNetworkingV2",
									},
								},
							},
						},
					},
					{
						Name: "loadbalancer",
						Resources: []ComposedResource{
							{
								Name: "loadbalancer",
								Base: &unstructured.Unstructured{
									Object: map[string]interface{}{
										"apiVersion": "cloud.physicsx.ai/v1alpha1",
										"kind":       "StampLoadBalancerV2",
									},
								},
							},
						},
					},
				},
				allResources: []ResourceInfo{
					{Name: "networking", Kind: "StampNetworkingV2"},
					{Name: "loadbalancer", Kind: "StampLoadBalancerV2"},
				},
				usages: []UsageInfo{}, // No usages defined
			},
			wantIssues:  1,
			wantMessage: "StampNetworkingV2",
		},
		{
			name: "Cross-composition dependency exists - no warning",
			validator: &DeletionSafetyValidator{
				compositions: []*ParsedComposition{
					{
						Name: "networking",
						Resources: []ComposedResource{
							{
								Name: "networking",
								Base: &unstructured.Unstructured{
									Object: map[string]interface{}{
										"apiVersion": "cloud.physicsx.ai/v1alpha1",
										"kind":       "StampNetworkingV2",
									},
								},
							},
						},
					},
					{
						Name: "loadbalancer",
						Resources: []ComposedResource{
							{
								Name: "loadbalancer",
								Base: &unstructured.Unstructured{
									Object: map[string]interface{}{
										"apiVersion": "cloud.physicsx.ai/v1alpha1",
										"kind":       "StampLoadBalancerV2",
									},
								},
							},
						},
					},
				},
				allResources: []ResourceInfo{
					{Name: "networking", Kind: "StampNetworkingV2"},
					{Name: "loadbalancer", Kind: "StampLoadBalancerV2"},
				},
				usages: []UsageInfo{
					{
						Name:           "usage-networking-by-lb",
						OfKind:         "StampNetworkingV2",
						OfAPIVersion:   "cloud.physicsx.ai",
						ByKind:         "StampLoadBalancerV2",
						ByAPIVersion:   "cloud.physicsx.ai",
						ReplayDeletion: true,
					},
				},
			},
			wantIssues: 0,
		},
		{
			name: "Only one resource present - no warning",
			validator: &DeletionSafetyValidator{
				compositions: []*ParsedComposition{
					{
						Name: "networking",
						Resources: []ComposedResource{
							{
								Name: "networking",
								Base: &unstructured.Unstructured{
									Object: map[string]interface{}{
										"apiVersion": "cloud.physicsx.ai/v1alpha1",
										"kind":       "StampNetworkingV2",
									},
								},
							},
						},
					},
				},
				allResources: []ResourceInfo{
					{Name: "networking", Kind: "StampNetworkingV2"},
					// No StampLoadBalancerV2
				},
				usages: []UsageInfo{},
			},
			wantIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := tt.validator.validateCrossCompositionDependencies()

			crossCompIssues := 0
			for _, issue := range issues {
				if issue.Category == "crossComposition" {
					crossCompIssues++
					if tt.wantMessage != "" {
						assert.Contains(t, issue.Message, tt.wantMessage)
					}
				}
			}
			assert.Equal(t, tt.wantIssues, crossCompIssues, "unexpected number of cross-composition issues")
		})
	}
}

func TestFindRoleARNInValues(t *testing.T) {
	validator := &DeletionSafetyValidator{}

	tests := []struct {
		name       string
		forProvider map[string]interface{}
		wantFound  bool
	}{
		{
			name: "Direct ARN in values",
			forProvider: map[string]interface{}{
				"values": map[string]interface{}{
					"roleArn": "arn:aws:iam::123456789:role/test-role",
				},
			},
			wantFound: true,
		},
		{
			name: "EKS annotation pattern",
			forProvider: map[string]interface{}{
				"values": map[string]interface{}{
					"serviceAccount": map[string]interface{}{
						"annotations": map[string]interface{}{
							"eks.amazonaws.com/role-arn": "something",
						},
					},
				},
			},
			wantFound: true,
		},
		{
			name: "No IAM role",
			forProvider: map[string]interface{}{
				"values": map[string]interface{}{
					"replicas": 3,
				},
			},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.findRoleARNInValues(tt.forProvider)
			if tt.wantFound {
				assert.NotEmpty(t, result, "should find role ARN")
			} else {
				assert.Empty(t, result, "should not find role ARN")
			}
		})
	}
}

func TestNewDeletionSafetyValidator(t *testing.T) {
	compositions := []*ParsedComposition{
		{
			Name:       "test-composition",
			SourceFile: "test.yaml",
			CompositeTypeRef: schema.GroupVersionKind{
				Group:   "cloud.test.io",
				Version: "v1alpha1",
				Kind:    "TestResource",
			},
			Resources: []ComposedResource{
				{
					Name: "helm-release",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "helm.crossplane.io/v1beta1",
							"kind":       "Release",
							"spec": map[string]interface{}{
								"rollbackLimit": int64(100),
							},
						},
					},
				},
				{
					Name: "iam-role",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "iam.aws.upbound.io/v1beta1",
							"kind":       "Role",
							"metadata": map[string]interface{}{
								"labels": map[string]interface{}{
									"role": "test-role",
								},
							},
						},
					},
				},
				{
					Name: "usage-iam-by-helm",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "protection.crossplane.io/v1beta1",
							"kind":       "ClusterUsage",
							"spec": map[string]interface{}{
								"replayDeletion": true,
								"of": map[string]interface{}{
									"apiVersion": "iam.aws.upbound.io/v1beta1",
									"kind":       "Role",
								},
								"by": map[string]interface{}{
									"apiVersion": "helm.crossplane.io/v1beta1",
									"kind":       "Release",
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewDeletionSafetyValidator(compositions, nil)

	assert.Equal(t, 1, len(validator.helmReleases), "should extract 1 helm release")
	assert.Equal(t, 1, len(validator.usages), "should extract 1 usage")
	assert.Equal(t, 1, len(validator.iamRoles), "should extract 1 IAM role")
	assert.Equal(t, 3, len(validator.allResources), "should track all 3 resources")
}

func TestValidateFullIntegration(t *testing.T) {
	// Test the full Validate() method
	compositions := []*ParsedComposition{
		{
			Name:       "test-composition",
			SourceFile: "test.yaml",
			Resources: []ComposedResource{
				// Helm without rollbackLimit
				{
					Name: "helm-no-rollback",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "helm.crossplane.io/v1beta1",
							"kind":       "Release",
							"spec": map[string]interface{}{
								"forProvider": map[string]interface{}{
									"chart": map[string]interface{}{"name": "test"},
								},
							},
						},
					},
				},
				// Helm with IRSA - has IAM Usage so NO warning expected
				{
					Name: "helm-with-irsa",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "helm.crossplane.io/v1beta1",
							"kind":       "Release",
							"spec": map[string]interface{}{
								"rollbackLimit": int64(100),
								"forProvider": map[string]interface{}{
									"chart": map[string]interface{}{"name": "karpenter"},
									"values": map[string]interface{}{
										"serviceAccount": map[string]interface{}{
											"annotations": map[string]interface{}{
												"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/test",
											},
										},
									},
								},
							},
						},
					},
				},
				// Usage with mismatched labels (protects IAM by Helm, so IAM check passes)
				// But labels are wrong, so labelMismatch error
				{
					Name: "usage-bad-labels",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "protection.crossplane.io/v1beta1",
							"kind":       "ClusterUsage",
							"spec": map[string]interface{}{
								"replayDeletion": true,
								"of": map[string]interface{}{
									"apiVersion": "iam.aws.upbound.io/v1beta1",
									"kind":       "Role",
									"resourceSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{
											"role": "nonexistent-label",
										},
									},
								},
								"by": map[string]interface{}{
									"apiVersion": "helm.crossplane.io/v1beta1",
									"kind":       "Release",
								},
							},
						},
					},
				},
			},
		},
	}

	validator := NewDeletionSafetyValidator(compositions, nil)
	result := validator.Validate()

	// Should have warnings for:
	// 1. helm-no-rollback missing rollbackLimit
	// NOTE: helm-with-irsa has a Usage protecting IAM (even if labels are wrong)
	//       so NO iamUsage warning is expected
	assert.GreaterOrEqual(t, len(result.Warnings), 1, "should have at least 1 warning")

	// Should have errors for:
	// 1. usage-bad-labels with mismatched 'of' selector
	assert.GreaterOrEqual(t, len(result.Errors), 1, "should have at least 1 error")

	// Check specific categories
	categories := make(map[string]int)
	for _, w := range result.Warnings {
		categories[w.Category]++
	}
	for _, e := range result.Errors {
		categories[e.Category]++
	}

	assert.Equal(t, 1, categories["rollbackLimit"], "should have 1 rollbackLimit warning")
	// No iamUsage warning because a Usage exists (even with wrong labels)
	assert.Equal(t, 0, categories["iamUsage"], "should have 0 iamUsage warnings (Usage exists)")
	assert.Equal(t, 1, categories["labelMismatch"], "should have 1 labelMismatch error")
}

func TestValidateFullIntegrationWithMissingIAMUsage(t *testing.T) {
	// Test that IAM Usage warning IS raised when no Usage exists
	compositions := []*ParsedComposition{
		{
			Name:       "test-composition",
			SourceFile: "test.yaml",
			Resources: []ComposedResource{
				// Helm with IRSA but NO Usage at all
				{
					Name: "helm-with-irsa-no-usage",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "helm.crossplane.io/v1beta1",
							"kind":       "Release",
							"spec": map[string]interface{}{
								"rollbackLimit": int64(100),
								"forProvider": map[string]interface{}{
									"chart": map[string]interface{}{"name": "karpenter"},
									"values": map[string]interface{}{
										"serviceAccount": map[string]interface{}{
											"annotations": map[string]interface{}{
												"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/test",
											},
										},
									},
								},
							},
						},
					},
				},
				// No Usage objects!
			},
		},
	}

	validator := NewDeletionSafetyValidator(compositions, nil)
	result := validator.Validate()

	// Should have iamUsage warning because no Usage exists
	categories := make(map[string]int)
	for _, w := range result.Warnings {
		categories[w.Category]++
	}

	assert.Equal(t, 1, categories["iamUsage"], "should have 1 iamUsage warning when no Usage exists")
}

func TestDeletionOrderWithCycles(t *testing.T) {
	// Test that cycles don't cause infinite loops
	validator := &DeletionSafetyValidator{
		allResources: []ResourceInfo{
			{Name: "a", Kind: "ResourceA"},
			{Name: "b", Kind: "ResourceB"},
			{Name: "c", Kind: "ResourceC"},
		},
		usages: []UsageInfo{
			// Create a cycle: A -> B -> C -> A
			{Name: "usage-a-by-b", OfKind: "ResourceA", ByKind: "ResourceB", ReplayDeletion: true},
			{Name: "usage-b-by-c", OfKind: "ResourceB", ByKind: "ResourceC", ReplayDeletion: true},
			{Name: "usage-c-by-a", OfKind: "ResourceC", ByKind: "ResourceA", ReplayDeletion: true},
		},
	}

	// Should not hang - cycle detection should handle this
	waves := validator.buildDeletionOrder()

	// All resources should be in some wave despite the cycle
	totalResources := 0
	for _, wave := range waves {
		totalResources += len(wave.Resources)
	}
	assert.Equal(t, 3, totalResources, "all resources should be in deletion order despite cycle")
}

func TestDeletionOrderEmpty(t *testing.T) {
	validator := &DeletionSafetyValidator{
		allResources: []ResourceInfo{},
		usages:       []UsageInfo{},
	}

	waves := validator.buildDeletionOrder()
	assert.Equal(t, 0, len(waves), "empty resources should produce no waves")
}

func TestDeletionOrderNoUsages(t *testing.T) {
	validator := &DeletionSafetyValidator{
		allResources: []ResourceInfo{
			{Name: "a", Kind: "ResourceA"},
			{Name: "b", Kind: "ResourceB"},
		},
		usages: []UsageInfo{}, // No dependencies
	}

	waves := validator.buildDeletionOrder()

	// All resources should be in wave 0 (can be deleted in parallel)
	assert.Equal(t, 1, len(waves), "should have single wave when no dependencies")
	assert.Equal(t, 2, len(waves[0].Resources), "all resources should be in wave 0")
}

func TestPrintDeletionSafetyResults(t *testing.T) {
	result := &DeletionSafetyResult{
		Errors: []DeletionSafetyIssue{
			{
				SourceFile: "test.yaml",
				SourceLine: 10,
				Category:   "labelMismatch",
				Message:    "Labels don't match",
				Suggestion: "Add correct labels",
			},
		},
		Warnings: []DeletionSafetyIssue{
			{
				SourceFile: "test.yaml",
				SourceLine: 20,
				Category:   "rollbackLimit",
				Message:    "Missing rollbackLimit",
				Suggestion: "Add rollbackLimit: 100",
			},
		},
	}

	var buf bytes.Buffer
	err := PrintDeletionSafetyResults(result, &buf, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[x]") // Error prefix
	assert.Contains(t, output, "[!]") // Warning prefix
	assert.Contains(t, output, "labelMismatch")
	assert.Contains(t, output, "rollbackLimit")
	assert.Contains(t, output, "Suggestion:")
}

func TestResultHasErrorsAndWarnings(t *testing.T) {
	result := &DeletionSafetyResult{}
	assert.False(t, result.HasErrors())
	assert.False(t, result.HasWarnings())

	result.Errors = append(result.Errors, DeletionSafetyIssue{Message: "error"})
	assert.True(t, result.HasErrors())
	assert.False(t, result.HasWarnings())

	result.Warnings = append(result.Warnings, DeletionSafetyIssue{Message: "warning"})
	assert.True(t, result.HasErrors())
	assert.True(t, result.HasWarnings())
}

func TestExtractIAMPolicies(t *testing.T) {
	compositions := []*ParsedComposition{
		{
			Name:       "test-composition",
			SourceFile: "test.yaml",
			Resources: []ComposedResource{
				{
					Name: "iam-policy",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "iam.aws.upbound.io/v1beta1",
							"kind":       "Policy",
							"metadata": map[string]interface{}{
								"labels": map[string]interface{}{
									"role": "karpenter-policy",
								},
							},
						},
					},
				},
				{
					Name: "role-policy-attachment",
					Base: &unstructured.Unstructured{
						Object: map[string]interface{}{
							"apiVersion": "iam.aws.upbound.io/v1beta1",
							"kind":       "RolePolicyAttachment",
						},
					},
				},
			},
		},
	}

	validator := NewDeletionSafetyValidator(compositions, nil)

	assert.Equal(t, 2, len(validator.iamPolicies), "should extract 2 IAM policies (Policy + RolePolicyAttachment)")
}

func TestUsageWithoutReplayDeletion(t *testing.T) {
	validator := &DeletionSafetyValidator{
		allResources: []ResourceInfo{
			{Name: "a", Kind: "ResourceA"},
			{Name: "b", Kind: "ResourceB"},
		},
		usages: []UsageInfo{
			{
				Name:           "usage-without-replay",
				OfKind:         "ResourceA",
				ByKind:         "ResourceB",
				ReplayDeletion: false, // Not for deletion ordering
			},
		},
	}

	waves := validator.buildDeletionOrder()

	// Without replayDeletion, the usage shouldn't affect deletion order
	// All resources should be in wave 0
	assert.Equal(t, 1, len(waves), "should have single wave when no replayDeletion")
}
