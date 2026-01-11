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
	"strings"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
)

// FunctionInputDiscovery discovers functions used in compositions and their input schemas.
type FunctionInputDiscovery struct {
	dynamicClient  dynamic.Interface
	fetcher        ImageFetcher
	cache          Cache
	writer         io.Writer
	discoveredFns  map[string]*DiscoveredFunction
	inputSchemas   map[schema.GroupVersionKind]*extv1.CustomResourceDefinition
}

// DiscoveredFunction represents a function discovered from compositions.
type DiscoveredFunction struct {
	Name        string   // Function name (e.g., crossplane-function-patch-and-transform)
	Package     string   // Package image reference
	InputGVKs   []schema.GroupVersionKind // Input GVKs used in compositions
	UsageCount  int
}

// NewFunctionInputDiscovery creates a new FunctionInputDiscovery.
func NewFunctionInputDiscovery(dynamicClient dynamic.Interface, fetcher ImageFetcher, cache Cache, w io.Writer) *FunctionInputDiscovery {
	return &FunctionInputDiscovery{
		dynamicClient: dynamicClient,
		fetcher:       fetcher,
		cache:         cache,
		writer:        w,
		discoveredFns: make(map[string]*DiscoveredFunction),
		inputSchemas:  make(map[schema.GroupVersionKind]*extv1.CustomResourceDefinition),
	}
}

// DiscoverFromCompositions scans compositions to find function references and their input GVKs.
func (d *FunctionInputDiscovery) DiscoverFromCompositions(objects []*unstructured.Unstructured) {
	for _, obj := range objects {
		// Check if this is a composition
		if obj.GetAPIVersion() != "apiextensions.crossplane.io/v1" || obj.GetKind() != "Composition" {
			continue
		}

		// Parse pipeline steps
		pipeline, found, _ := unstructured.NestedSlice(obj.Object, "spec", "pipeline")
		if !found {
			continue
		}

		for _, step := range pipeline {
			stepMap, ok := step.(map[string]interface{})
			if !ok {
				continue
			}

			// Get function reference
			functionRef, ok := stepMap["functionRef"].(map[string]interface{})
			if !ok {
				continue
			}

			fnName, _ := functionRef["name"].(string)
			if fnName == "" {
				continue
			}

			// Get input GVK
			input, ok := stepMap["input"].(map[string]interface{})
			if !ok {
				continue
			}

			apiVersion, _ := input["apiVersion"].(string)
			kind, _ := input["kind"].(string)

			if apiVersion == "" || kind == "" {
				continue
			}

			// Parse GVK
			gv := strings.Split(apiVersion, "/")
			var group, version string
			if len(gv) == 2 {
				group = gv[0]
				version = gv[1]
			} else {
				version = gv[0]
			}

			gvk := schema.GroupVersionKind{
				Group:   group,
				Version: version,
				Kind:    kind,
			}

			// Track function
			if _, exists := d.discoveredFns[fnName]; !exists {
				d.discoveredFns[fnName] = &DiscoveredFunction{
					Name:      fnName,
					InputGVKs: make([]schema.GroupVersionKind, 0),
				}
			}

			d.discoveredFns[fnName].UsageCount++

			// Add GVK if not already present
			found := false
			for _, existingGVK := range d.discoveredFns[fnName].InputGVKs {
				if existingGVK == gvk {
					found = true
					break
				}
			}
			if !found {
				d.discoveredFns[fnName].InputGVKs = append(d.discoveredFns[fnName].InputGVKs, gvk)
			}
		}
	}
}

// ResolvePackagesFromCluster looks up function packages from installed Function resources.
func (d *FunctionInputDiscovery) ResolvePackagesFromCluster(ctx context.Context) error {
	if d.dynamicClient == nil {
		return nil
	}

	functionGVR := schema.GroupVersionResource{
		Group:    "pkg.crossplane.io",
		Version:  "v1",
		Resource: "functions",
	}

	list, err := d.dynamicClient.Resource(functionGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Functions might not be installed, that's OK
		return nil
	}

	for _, item := range list.Items {
		fnName := item.GetName()
		if fn, exists := d.discoveredFns[fnName]; exists {
			pkg, _, _ := unstructured.NestedString(item.Object, "spec", "package")
			if pkg != "" {
				fn.Package = pkg
			}
		}
	}

	return nil
}

// DownloadInputSchemas downloads function packages and extracts input CRD schemas.
func (d *FunctionInputDiscovery) DownloadInputSchemas() error {
	for _, fn := range d.discoveredFns {
		if fn.Package == "" {
			continue
		}

		var schemas [][]byte

		// Check if cache exists - Exists() returns empty string if already cached
		if d.cache != nil {
			cachePath, err := d.cache.Exists(fn.Package)
			if err == nil && cachePath == "" {
				// Already cached, load from cache
				cachedSchemas, loadErr := d.cache.Load(fn.Package)
				if loadErr == nil && len(cachedSchemas) > 0 {
					// Parse cached CRDs
					for _, obj := range cachedSchemas {
						if obj.GetAPIVersion() != "apiextensions.k8s.io/v1" || obj.GetKind() != "CustomResourceDefinition" {
							continue
						}
						
						crd := &extv1.CustomResourceDefinition{}
						data, marshalErr := obj.MarshalJSON()
						if marshalErr != nil {
							continue
						}
						if unmarshalErr := yaml.Unmarshal(data, crd); unmarshalErr != nil {
							continue
						}
						
						// Index by GVK
						for _, ver := range crd.Spec.Versions {
							gvk := schema.GroupVersionKind{
								Group:   crd.Spec.Group,
								Version: ver.Name,
								Kind:    crd.Spec.Names.Kind,
							}
							d.inputSchemas[gvk] = crd
						}
					}
					continue
				}
			}
		}

		if _, err := fmt.Fprintf(d.writer, "Downloading function package: %s\n", fn.Package); err != nil {
			return errors.Wrap(err, "cannot write output")
		}

		// Try to fetch the base layer (contains CRDs)
		layer, err := d.fetcher.FetchBaseLayer(fn.Package)
		if err != nil {
			if _, wErr := fmt.Fprintf(d.writer, "[!] Warning: cannot download function %s: %v\n", fn.Package, err); wErr != nil {
				return errors.Wrap(wErr, "cannot write warning")
			}
			continue
		}

		// Extract CRDs from the package
		schemas, _, err = extractPackageContent(*layer)
		if err != nil {
			if _, wErr := fmt.Fprintf(d.writer, "[!] Warning: cannot extract schemas from %s: %v\n", fn.Package, err); wErr != nil {
				return errors.Wrap(wErr, "cannot write warning")
			}
			continue
		}

		// Cache the schemas for future use
		if d.cache != nil {
			cachePath, cacheErr := d.cache.Exists(fn.Package)
			if cacheErr == nil && cachePath != "" {
				if storeErr := d.cache.Store(schemas, cachePath); storeErr != nil {
					// Just log warning, don't fail
					if _, wErr := fmt.Fprintf(d.writer, "[!] Warning: cannot cache function %s: %v\n", fn.Package, storeErr); wErr != nil {
						return errors.Wrap(wErr, "cannot write warning")
					}
				}
			}
		}

		// Parse CRDs
		for _, schemaBytes := range schemas {
			var obj unstructured.Unstructured
			if err := yaml.Unmarshal(schemaBytes, &obj); err != nil {
				continue
			}

			if obj.GetAPIVersion() != "apiextensions.k8s.io/v1" || obj.GetKind() != "CustomResourceDefinition" {
				continue
			}

			crd := &extv1.CustomResourceDefinition{}
			if err := yaml.Unmarshal(schemaBytes, crd); err != nil {
				continue
			}

			// Index by GVK
			for _, ver := range crd.Spec.Versions {
				gvk := schema.GroupVersionKind{
					Group:   crd.Spec.Group,
					Version: ver.Name,
					Kind:    crd.Spec.Names.Kind,
				}
				d.inputSchemas[gvk] = crd
			}
		}
	}

	return nil
}

// GetInputCRDs returns all discovered function input CRDs.
func (d *FunctionInputDiscovery) GetInputCRDs() []*extv1.CustomResourceDefinition {
	result := make([]*extv1.CustomResourceDefinition, 0, len(d.inputSchemas))
	seen := make(map[string]bool)

	for _, crd := range d.inputSchemas {
		if !seen[crd.Name] {
			result = append(result, crd)
			seen[crd.Name] = true
		}
	}

	return result
}

// GetDiscoveredFunctions returns discovered functions.
func (d *FunctionInputDiscovery) GetDiscoveredFunctions() []*DiscoveredFunction {
	result := make([]*DiscoveredFunction, 0, len(d.discoveredFns))
	for _, fn := range d.discoveredFns {
		result = append(result, fn)
	}
	return result
}

// PrintDiscoveryReport prints what was discovered.
func (d *FunctionInputDiscovery) PrintDiscoveryReport(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "\n=== Function Discovery ===\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if len(d.discoveredFns) == 0 {
		if _, err := fmt.Fprintf(w, "No functions found in compositions.\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
		return nil
	}

	if _, err := fmt.Fprintf(w, "Discovered %d functions:\n", len(d.discoveredFns)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	for _, fn := range d.discoveredFns {
		gvks := make([]string, 0, len(fn.InputGVKs))
		for _, gvk := range fn.InputGVKs {
			gvks = append(gvks, gvk.String())
		}

		pkg := fn.Package
		if pkg == "" {
			pkg = "(not resolved)"
		}

		if _, err := fmt.Fprintf(w, "  - %s (%d usages)\n    Package: %s\n    Inputs: %s\n",
			fn.Name, fn.UsageCount, pkg, strings.Join(gvks, ", ")); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	if _, err := fmt.Fprintf(w, "\nExtracted %d input CRDs from function packages.\n", len(d.inputSchemas)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	return nil
}
