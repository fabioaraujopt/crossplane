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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
)

// ClusterSchemaFetcher fetches CRD schemas from a live Kubernetes cluster.
type ClusterSchemaFetcher struct {
	kubeconfig    string
	context       string
	dynamicClient dynamic.Interface
	clientset     *kubernetes.Clientset
	writer        io.Writer
	cacheDir      string
	cacheTTL      time.Duration
}

// NewClusterSchemaFetcher creates a new ClusterSchemaFetcher.
func NewClusterSchemaFetcher(kubeconfig, kubeContext, cacheDir string, w io.Writer) (*ClusterSchemaFetcher, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		// Use explicit kubeconfig file
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
		configOverrides := &clientcmd.ConfigOverrides{}
		if kubeContext != "" {
			configOverrides.CurrentContext = kubeContext
		}
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules, configOverrides).ClientConfig()
	} else {
		// Use default kubeconfig loading rules (KUBECONFIG env, ~/.kube/config)
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		if kubeContext != "" {
			configOverrides.CurrentContext = kubeContext
		}
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules, configOverrides).ClientConfig()
	}

	if err != nil {
		return nil, errors.Wrap(err, "cannot create kubernetes config")
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create dynamic client")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create kubernetes clientset")
	}

	// Default cache TTL is 1 hour
	return &ClusterSchemaFetcher{
		kubeconfig:    kubeconfig,
		context:       kubeContext,
		dynamicClient: dynamicClient,
		clientset:     clientset,
		writer:        w,
		cacheDir:      cacheDir,
		cacheTTL:      1 * time.Hour,
	}, nil
}

// FetchAllCRDs fetches all CRDs from the cluster.
func (f *ClusterSchemaFetcher) FetchAllCRDs(ctx context.Context) ([]*extv1.CustomResourceDefinition, error) {
	crdGVR := schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}

	list, err := f.dynamicClient.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "cannot list CRDs from cluster")
	}

	crds := make([]*extv1.CustomResourceDefinition, 0, len(list.Items))
	for _, item := range list.Items {
		crd, err := unstructuredToCRD(&item)
		if err != nil {
			// Log warning but continue
			if _, wErr := fmt.Fprintf(f.writer, "[!] Warning: cannot convert CRD %s: %v\n", item.GetName(), err); wErr != nil {
				return nil, errors.Wrap(wErr, "cannot write warning")
			}
			continue
		}
		crds = append(crds, crd)
	}

	return crds, nil
}

// getCacheKey generates a cache key for the cluster context and API groups.
func (f *ClusterSchemaFetcher) getCacheKey(apiGroups []string) string {
	// Use context name + sorted API groups to generate cache key
	key := f.context
	if key == "" {
		key = "default"
	}
	for _, g := range apiGroups {
		key += ":" + g
	}
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:16])
}

// getCachePath returns the path to the cache file.
func (f *ClusterSchemaFetcher) getCachePath(cacheKey string) string {
	return filepath.Join(f.cacheDir, "cluster-crds", f.context, cacheKey+".yaml")
}

// loadFromCache attempts to load CRDs from cache.
func (f *ClusterSchemaFetcher) loadFromCache(apiGroups []string) ([]*extv1.CustomResourceDefinition, bool) {
	if f.cacheDir == "" {
		return nil, false
	}

	cacheKey := f.getCacheKey(apiGroups)
	cachePath := f.getCachePath(cacheKey)

	info, err := os.Stat(cachePath)
	if err != nil {
		return nil, false
	}

	// Check if cache is expired
	if time.Since(info.ModTime()) > f.cacheTTL {
		return nil, false
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false
	}

	// Parse cached CRDs
	var crdList extv1.CustomResourceDefinitionList
	if err := yaml.Unmarshal(data, &crdList); err != nil {
		return nil, false
	}

	crds := make([]*extv1.CustomResourceDefinition, len(crdList.Items))
	for i := range crdList.Items {
		crds[i] = &crdList.Items[i]
	}

	return crds, true
}

// saveToCache saves CRDs to cache.
func (f *ClusterSchemaFetcher) saveToCache(apiGroups []string, crds []*extv1.CustomResourceDefinition) error {
	if f.cacheDir == "" {
		return nil
	}

	cacheKey := f.getCacheKey(apiGroups)
	cachePath := f.getCachePath(cacheKey)

	// Ensure cache directory exists
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		return errors.Wrap(err, "cannot create cache directory")
	}

	// Create CRD list for caching
	crdList := extv1.CustomResourceDefinitionList{
		Items: make([]extv1.CustomResourceDefinition, len(crds)),
	}
	for i, crd := range crds {
		crdList.Items[i] = *crd
	}

	data, err := yaml.Marshal(&crdList)
	if err != nil {
		return errors.Wrap(err, "cannot marshal CRDs to YAML")
	}

	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		return errors.Wrap(err, "cannot write cache file")
	}

	return nil
}

// FetchCRDsForAPIGroups fetches CRDs for specific API groups from the cluster.
func (f *ClusterSchemaFetcher) FetchCRDsForAPIGroups(ctx context.Context, apiGroups []string) ([]*extv1.CustomResourceDefinition, error) {
	allCRDs, err := f.FetchAllCRDs(ctx)
	if err != nil {
		return nil, err
	}

	// Filter CRDs by API group
	filtered := make([]*extv1.CustomResourceDefinition, 0)
	groupSet := make(map[string]bool)
	for _, g := range apiGroups {
		groupSet[g] = true
	}

	for _, crd := range allCRDs {
		if groupSet[crd.Spec.Group] {
			filtered = append(filtered, crd)
		}
	}

	return filtered, nil
}

// FetchCRDsForGVKs fetches CRDs for specific GroupVersionKinds from the cluster.
func (f *ClusterSchemaFetcher) FetchCRDsForGVKs(ctx context.Context, gvks []schema.GroupVersionKind) ([]*extv1.CustomResourceDefinition, error) {
	allCRDs, err := f.FetchAllCRDs(ctx)
	if err != nil {
		return nil, err
	}

	// Build a set of groups we need
	groupSet := make(map[string]bool)
	for _, gvk := range gvks {
		groupSet[gvk.Group] = true
	}

	// Filter CRDs by API group
	filtered := make([]*extv1.CustomResourceDefinition, 0)
	for _, crd := range allCRDs {
		if groupSet[crd.Spec.Group] {
			filtered = append(filtered, crd)
		}
	}

	return filtered, nil
}

// DiscoverAndFetch discovers which CRDs are needed from compositions and fetches them from the cluster.
func (f *ClusterSchemaFetcher) DiscoverAndFetch(ctx context.Context, objects []*unstructured.Unstructured) ([]*extv1.CustomResourceDefinition, error) {
	// Discover API groups from compositions
	discovery := NewProviderDiscovery()
	discovery.DiscoverFromUnstructured(objects)

	// Collect all API groups (both known and unknown)
	apiGroups := make([]string, 0)
	
	// Always include Crossplane core API groups for validating compositions themselves
	apiGroups = append(apiGroups,
		"apiextensions.crossplane.io", // Composition, XRD CRDs
		"pkg.crossplane.io",           // Provider, Function, Configuration CRDs
	)
	
	for _, provider := range discovery.GetDiscoveredProviders() {
		apiGroups = append(apiGroups, provider.APIGroup)
	}
	
	for group := range discovery.GetUnknownAPIGroups() {
		apiGroups = append(apiGroups, group)
	}

	if len(apiGroups) == 0 {
		return nil, nil
	}

	// Try to load from cache first
	if crds, ok := f.loadFromCache(apiGroups); ok {
		if _, err := fmt.Fprintf(f.writer, "Loaded %d CRDs from cache for %d API groups\n", len(crds), len(apiGroups)); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}
		return crds, nil
	}

	if _, err := fmt.Fprintf(f.writer, "Fetching CRDs from cluster for %d API groups...\n", len(apiGroups)); err != nil {
		return nil, errors.Wrap(err, "cannot write output")
	}

	crds, err := f.FetchCRDsForAPIGroups(ctx, apiGroups)
	if err != nil {
		return nil, err
	}

	// Save to cache
	if err := f.saveToCache(apiGroups, crds); err != nil {
		// Just log warning, don't fail
		if _, wErr := fmt.Fprintf(f.writer, "[!] Warning: cannot save CRDs to cache: %v\n", err); wErr != nil {
			return nil, errors.Wrap(wErr, "cannot write warning")
		}
	}

	return crds, nil
}

// PrintDiscoveryReport prints what was discovered and fetched.
func (f *ClusterSchemaFetcher) PrintDiscoveryReport(crds []*extv1.CustomResourceDefinition, w io.Writer) error {
	if _, err := fmt.Fprintf(w, "\n=== Cluster CRD Discovery ===\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if len(crds) == 0 {
		if _, err := fmt.Fprintf(w, "No CRDs fetched from cluster.\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
		return nil
	}

	// Group by API group
	byGroup := make(map[string][]string)
	for _, crd := range crds {
		group := crd.Spec.Group
		byGroup[group] = append(byGroup[group], crd.Spec.Names.Kind)
	}

	if _, err := fmt.Fprintf(w, "Fetched %d CRDs from cluster:\n", len(crds)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	for group, kinds := range byGroup {
		if _, err := fmt.Fprintf(w, "  - %s (%d kinds: %s)\n",
			group, len(kinds), strings.Join(kinds, ", ")); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	return nil
}

// unstructuredToCRD converts an unstructured object to a CRD.
func unstructuredToCRD(u *unstructured.Unstructured) (*extv1.CustomResourceDefinition, error) {
	crd := &extv1.CustomResourceDefinition{}
	
	// Use runtime.DefaultUnstructuredConverter to convert
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, crd); err != nil {
		return nil, errors.Wrap(err, "cannot convert unstructured to CRD")
	}

	return crd, nil
}
