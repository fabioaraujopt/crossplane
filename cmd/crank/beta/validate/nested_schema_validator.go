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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NestedResourceInfo contains information about a nested resource inside a base.
type NestedResourceInfo struct {
	// ParentPath is the path prefix that contains the nested resource (e.g., "spec.forProvider.manifest")
	ParentPath string
	// NestedGVK is the GVK of the nested resource
	NestedGVK schema.GroupVersionKind
	// NestedContent is the unstructured content of the nested resource
	NestedContent *unstructured.Unstructured
}

// WellKnownNestedPaths defines paths that contain nested Kubernetes resources.
// These paths typically have x-kubernetes-preserve-unknown-fields: true
var WellKnownNestedPaths = map[string][]string{
	// provider-kubernetes Object
	"kubernetes.crossplane.io/v1alpha2.Object": {"spec.forProvider.manifest"},
	"kubernetes.crossplane.io/v1alpha1.Object": {"spec.forProvider.manifest"},
	// provider-helm Release (values is arbitrary, but we can try to validate chart structure)
	"helm.crossplane.io/v1beta1.Release": {"spec.forProvider.values"},
}

// ExtractNestedResources extracts nested resources from a base resource.
// For example, extracts the NodePool from inside an Object's manifest field.
func ExtractNestedResources(base *unstructured.Unstructured) []NestedResourceInfo {
	if base == nil {
		return nil
	}

	var results []NestedResourceInfo

	gvk := base.GroupVersionKind()
	key := gvk.GroupVersion().String() + "." + gvk.Kind

	paths, ok := WellKnownNestedPaths[key]
	if !ok {
		return nil
	}

	for _, path := range paths {
		nested := extractNestedAtPath(base, path)
		if nested != nil {
			results = append(results, *nested)
		}
	}

	return results
}

// extractNestedAtPath extracts a nested resource at a specific path.
func extractNestedAtPath(base *unstructured.Unstructured, path string) *NestedResourceInfo {
	parts := strings.Split(path, ".")
	
	// Navigate to the nested object
	current := base.Object
	for _, part := range parts {
		if current == nil {
			return nil
		}
		next, ok := current[part].(map[string]interface{})
		if !ok {
			return nil
		}
		current = next
	}

	if current == nil {
		return nil
	}

	// Check if it has apiVersion and kind
	apiVersion, hasAPIVersion := current["apiVersion"].(string)
	kind, hasKind := current["kind"].(string)
	if !hasAPIVersion || !hasKind {
		return nil
	}

	// Parse GVK
	gv := strings.Split(apiVersion, "/")
	var group, version string
	if len(gv) == 2 {
		group = gv[0]
		version = gv[1]
	} else {
		version = apiVersion
	}

	return &NestedResourceInfo{
		ParentPath: path,
		NestedGVK: schema.GroupVersionKind{
			Group:   group,
			Version: version,
			Kind:    kind,
		},
		NestedContent: &unstructured.Unstructured{Object: current},
	}
}

// GetNestedPath extracts the path inside a nested resource.
// For example, if fullPath is "spec.forProvider.manifest.spec.template.spec.requirements[0]"
// and parentPath is "spec.forProvider.manifest", returns "spec.template.spec.requirements[0]"
func GetNestedPath(fullPath, parentPath string) string {
	if !strings.HasPrefix(fullPath, parentPath+".") {
		return ""
	}
	return strings.TrimPrefix(fullPath, parentPath+".")
}

// IsPathInNestedResource checks if a path goes into a nested resource.
func IsPathInNestedResource(path string, nestedInfos []NestedResourceInfo) *NestedResourceInfo {
	for i := range nestedInfos {
		if strings.HasPrefix(path, nestedInfos[i].ParentPath+".") {
			return &nestedInfos[i]
		}
	}
	return nil
}
