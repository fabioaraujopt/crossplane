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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
)

const (
	// Default retry settings for HTTP requests
	defaultMaxRetries     = 3
	defaultRetryBaseDelay = 1 * time.Second
	defaultRetryMaxDelay  = 10 * time.Second
)

// httpDoWithRetry performs an HTTP request with retry logic for transient errors.
// It retries on 5xx errors, connection errors, and timeouts with exponential backoff.
func httpDoWithRetry(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	var lastErr error
	
	for attempt := 0; attempt < defaultMaxRetries; attempt++ {
		// Clone the request for retry (body may have been consumed)
		reqCopy := req.Clone(ctx)
		
		resp, err := client.Do(reqCopy)
		if err != nil {
			lastErr = err
			// Retry on connection errors
			if shouldRetry(err, nil) {
				waitForRetry(ctx, attempt)
				continue
			}
			return nil, err
		}
		
		// Check if we should retry based on status code
		if shouldRetryStatusCode(resp.StatusCode) {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
			waitForRetry(ctx, attempt)
			continue
		}
		
		return resp, nil
	}
	
	return nil, fmt.Errorf("failed after %d retries: %w", defaultMaxRetries, lastErr)
}

// shouldRetry returns true if the error is a transient error worth retrying.
func shouldRetry(err error, resp *http.Response) bool {
	if err != nil {
		// Retry on timeout, connection reset, etc.
		errStr := err.Error()
		return strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "connection reset") ||
			strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "no such host") ||
			strings.Contains(errStr, "EOF")
	}
	return false
}

// shouldRetryStatusCode returns true if the HTTP status code indicates a transient error.
func shouldRetryStatusCode(statusCode int) bool {
	// Retry on 5xx (server errors), 429 (rate limit), and 408 (timeout)
	return statusCode >= 500 || statusCode == 429 || statusCode == 408
}

// waitForRetry waits with exponential backoff before the next retry attempt.
func waitForRetry(ctx context.Context, attempt int) {
	// Exponential backoff with jitter: base * 2^attempt + random jitter
	delay := defaultRetryBaseDelay * time.Duration(1<<attempt)
	if delay > defaultRetryMaxDelay {
		delay = defaultRetryMaxDelay
	}
	// Add jitter (0-25% of delay)
	jitter := time.Duration(rand.Int63n(int64(delay / 4)))
	delay += jitter
	
	select {
	case <-time.After(delay):
	case <-ctx.Done():
	}
}

// CRDSourceType defines the type of CRD source.
type CRDSourceType string

const (
	// CRDSourceTypeGitHub fetches CRDs from a GitHub repository.
	CRDSourceTypeGitHub CRDSourceType = "github"
	// CRDSourceTypeCatalog fetches CRDs from the Datree CRDs catalog.
	CRDSourceTypeCatalog CRDSourceType = "catalog"
	// CRDSourceTypeLocal loads CRDs from a local directory.
	CRDSourceTypeLocal CRDSourceType = "local"
	// CRDSourceTypeCluster fetches CRDs from a Kubernetes cluster.
	CRDSourceTypeCluster CRDSourceType = "cluster"
	// CRDSourceTypeK8sSchemas fetches core K8s JSON schemas and converts to CRD format.
	CRDSourceTypeK8sSchemas CRDSourceType = "k8s-schemas"
)

// CRDSource represents a source for CRD schemas.
type CRDSource struct {
	Type     CRDSourceType
	Location string // URL, path, or repo reference
	Branch   string // For GitHub sources
	Path     string // Path within repo for GitHub sources
}

// ParseCRDSource parses a CRD source string into a CRDSource struct.
// Supported formats:
//   - github:org/repo:branch:path (e.g., github:crossplane-contrib/provider-helm:main:package/crds)
//   - local:/path/to/crds
//   - catalog:https://url (e.g., catalog:https://raw.githubusercontent.com/datreeio/CRDs-catalog/main)
//   - cluster (uses current kubeconfig)
func ParseCRDSource(source string) (CRDSource, error) {
	if source == "cluster" {
		return CRDSource{Type: CRDSourceTypeCluster}, nil
	}

	parts := strings.SplitN(source, ":", 2)
	if len(parts) < 2 {
		return CRDSource{}, fmt.Errorf("invalid source format: %s (expected type:location)", source)
	}

	sourceType := parts[0]
	switch sourceType {
	case "github":
		// github:org/repo:branch:path
		rest := parts[1]
		githubParts := strings.SplitN(rest, ":", 3)
		if len(githubParts) < 3 {
			return CRDSource{}, fmt.Errorf("invalid github source: %s (expected github:org/repo:branch:path)", source)
		}
		return CRDSource{
			Type:     CRDSourceTypeGitHub,
			Location: githubParts[0],
			Branch:   githubParts[1],
			Path:     githubParts[2],
		}, nil

	case "local":
		return CRDSource{
			Type:     CRDSourceTypeLocal,
			Location: parts[1],
		}, nil

	case "catalog":
		return CRDSource{
			Type:     CRDSourceTypeCatalog,
			Location: parts[1],
		}, nil

	case "k8s":
		// k8s:v1.29.0 -> fetch from yannh/kubernetes-json-schema
		return CRDSource{
			Type:     CRDSourceTypeK8sSchemas,
			Location: parts[1], // K8s version like "v1.29.0"
		}, nil

	default:
		return CRDSource{}, fmt.Errorf("unknown source type: %s (supported: github, local, catalog, cluster, k8s)", sourceType)
	}
}

// KindToDefaultAPIVersion maps Kind to its default apiVersion for resources missing apiVersion.
// This handles embedded manifests in kubernetes.crossplane.io/v1alpha2 Object resources
// that may omit apiVersion (the Object controller infers it, but the validator needs it explicit).
var KindToDefaultAPIVersion = map[string]string{
	// Core Kubernetes types (v1)
	"Namespace":             "v1",
	"Secret":                "v1",
	"ConfigMap":             "v1",
	"Service":               "v1",
	"ServiceAccount":        "v1",
	"PersistentVolumeClaim": "v1",
	"Pod":                   "v1",
	"Endpoints":             "v1",
	// RBAC types
	"Role":               "rbac.authorization.k8s.io/v1",
	"RoleBinding":        "rbac.authorization.k8s.io/v1",
	"ClusterRole":        "rbac.authorization.k8s.io/v1",
	"ClusterRoleBinding": "rbac.authorization.k8s.io/v1",
	// Apps types
	"Deployment":  "apps/v1",
	"StatefulSet": "apps/v1",
	"DaemonSet":   "apps/v1",
	"ReplicaSet":  "apps/v1",
	// Batch types
	"Job":     "batch/v1",
	"CronJob": "batch/v1",
	// Networking types
	"Ingress":       "networking.k8s.io/v1",
	"NetworkPolicy": "networking.k8s.io/v1",
	"IngressClass":  "networking.k8s.io/v1",
	// Storage types
	"StorageClass": "storage.k8s.io/v1",
	// Policy types
	"PodDisruptionBudget": "policy/v1",
	// Scheduling types
	"PriorityClass": "scheduling.k8s.io/v1",
	// Autoscaling types
	"HorizontalPodAutoscaler": "autoscaling/v2",
	// Istio types
	"VirtualService":       "networking.istio.io/v1beta1",
	"DestinationRule":      "networking.istio.io/v1beta1",
	"Gateway":              "networking.istio.io/v1beta1",
	"ServiceEntry":         "networking.istio.io/v1beta1",
	"AuthorizationPolicy":  "security.istio.io/v1beta1",
	"PeerAuthentication":   "security.istio.io/v1beta1",
	"RequestAuthentication":"security.istio.io/v1beta1",
	// Cert-manager types
	"Certificate":   "cert-manager.io/v1",
	"ClusterIssuer": "cert-manager.io/v1",
	"Issuer":        "cert-manager.io/v1",
	// External Secrets types
	"SecretStore":        "external-secrets.io/v1beta1",
	"ClusterSecretStore": "external-secrets.io/v1beta1",
	"ExternalSecret":     "external-secrets.io/v1beta1",
}

// CoreK8sTypes maps GVK strings to their group/version/kind for fetching from kubernetes-json-schema.
// These are Kubernetes built-in types that don't have CRDs but can be validated using JSON schemas.
var CoreK8sTypes = map[string]struct {
	Group   string
	Version string
	Kind    string
}{
	"v1, Kind=Secret":                                                          {Group: "", Version: "v1", Kind: "Secret"},
	"v1, Kind=ConfigMap":                                                       {Group: "", Version: "v1", Kind: "ConfigMap"},
	"v1, Kind=Namespace":                                                       {Group: "", Version: "v1", Kind: "Namespace"},
	"v1, Kind=Service":                                                         {Group: "", Version: "v1", Kind: "Service"},
	"v1, Kind=ServiceAccount":                                                  {Group: "", Version: "v1", Kind: "ServiceAccount"},
	"v1, Kind=PersistentVolumeClaim":                                           {Group: "", Version: "v1", Kind: "PersistentVolumeClaim"},
	"rbac.authorization.k8s.io/v1, Kind=Role":                                  {Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "Role"},
	"rbac.authorization.k8s.io/v1, Kind=RoleBinding":                           {Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"},
	"rbac.authorization.k8s.io/v1, Kind=ClusterRole":                           {Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"},
	"rbac.authorization.k8s.io/v1, Kind=ClusterRoleBinding":                    {Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"},
	"storage.k8s.io/v1, Kind=StorageClass":                                     {Group: "storage.k8s.io", Version: "v1", Kind: "StorageClass"},
	"scheduling.k8s.io/v1, Kind=PriorityClass":                                 {Group: "scheduling.k8s.io", Version: "v1", Kind: "PriorityClass"},
	"admissionregistration.k8s.io/v1, Kind=MutatingWebhookConfiguration":       {Group: "admissionregistration.k8s.io", Version: "v1", Kind: "MutatingWebhookConfiguration"},
	"admissionregistration.k8s.io/v1, Kind=ValidatingWebhookConfiguration":     {Group: "admissionregistration.k8s.io", Version: "v1", Kind: "ValidatingWebhookConfiguration"},
	"networking.k8s.io/v1, Kind=Ingress":                                       {Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"},
	"networking.k8s.io/v1, Kind=NetworkPolicy":                                 {Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"},
	"networking.k8s.io/v1, Kind=IngressClass":                                  {Group: "networking.k8s.io", Version: "v1", Kind: "IngressClass"},
	"apps/v1, Kind=Deployment":                                                 {Group: "apps", Version: "v1", Kind: "Deployment"},
	"apps/v1, Kind=StatefulSet":                                                {Group: "apps", Version: "v1", Kind: "StatefulSet"},
	"apps/v1, Kind=DaemonSet":                                                  {Group: "apps", Version: "v1", Kind: "DaemonSet"},
	"apps/v1, Kind=ReplicaSet":                                                 {Group: "apps", Version: "v1", Kind: "ReplicaSet"},
	"batch/v1, Kind=Job":                                                       {Group: "batch", Version: "v1", Kind: "Job"},
	"batch/v1, Kind=CronJob":                                                   {Group: "batch", Version: "v1", Kind: "CronJob"},
	"policy/v1, Kind=PodDisruptionBudget":                                      {Group: "policy", Version: "v1", Kind: "PodDisruptionBudget"},
	"autoscaling/v1, Kind=HorizontalPodAutoscaler":                             {Group: "autoscaling", Version: "v1", Kind: "HorizontalPodAutoscaler"},
	"autoscaling/v2, Kind=HorizontalPodAutoscaler":                             {Group: "autoscaling", Version: "v2", Kind: "HorizontalPodAutoscaler"},
}

// CRDSourceFetcher fetches CRDs from various sources.
type CRDSourceFetcher struct {
	cacheDir    string
	httpClient  *http.Client
	writer      io.Writer
	parallelism int
	githubToken string // GitHub personal access token for private repos
}

// NewCRDSourceFetcher creates a new CRDSourceFetcher.
func NewCRDSourceFetcher(cacheDir string, w io.Writer) *CRDSourceFetcher {
	return &CRDSourceFetcher{
		cacheDir: cacheDir,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		writer:      w,
		parallelism: 10, // default
	}
}

// SetGitHubToken sets the GitHub token for accessing private repositories.
func (f *CRDSourceFetcher) SetGitHubToken(token string) {
	f.githubToken = token
}

// addGitHubHeaders adds required headers for GitHub API requests, including auth if token is set.
func (f *CRDSourceFetcher) addGitHubHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if f.githubToken != "" {
		req.Header.Set("Authorization", "token "+f.githubToken)
	}
}

// SetParallelism sets the number of parallel fetch operations.
func (f *CRDSourceFetcher) SetParallelism(n int) {
	if n > 0 {
		f.parallelism = n
	}
}

// CleanCache removes all cached CRDs.
func (f *CRDSourceFetcher) CleanCache() error {
	cacheDir := filepath.Join(f.cacheDir, "crd-sources")
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return nil // Nothing to clean
	}
	return os.RemoveAll(cacheDir)
}

// sourceResult holds the result of fetching from a single source.
type sourceResult struct {
	source CRDSource
	crds   []*extv1.CustomResourceDefinition
	err    error
}

// PrefetchAllFromSources downloads ALL CRDs from all sources in parallel.
// This is useful for pre-populating the cache in Docker images.
// Returns all CRDs found and any errors encountered (non-fatal - continues on error).
func (f *CRDSourceFetcher) PrefetchAllFromSources(ctx context.Context, sources []CRDSource) ([]*extv1.CustomResourceDefinition, []error) {
	if _, err := fmt.Fprintf(f.writer, "\n=== Prefetching ALL CRDs from %d sources (parallel=%d) ===\n\n", len(sources), f.parallelism); err != nil {
		return nil, []error{errors.Wrap(err, "cannot write output")}
	}

	// Create a channel for results and a semaphore for parallelism
	results := make(chan sourceResult, len(sources))
	sem := make(chan struct{}, f.parallelism)

	var wg sync.WaitGroup

	// Launch parallel fetches
	for _, source := range sources {
		wg.Add(1)
		go func(src CRDSource) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			crds, err := f.prefetchAllFromSource(ctx, src)
			results <- sourceResult{source: src, crds: crds, err: err}
		}(source)
	}

	// Wait for all fetches to complete and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allCRDs []*extv1.CustomResourceDefinition
	var allErrors []error
	successCount := 0
	crdCount := 0

	for result := range results {
		if result.err != nil {
			allErrors = append(allErrors, fmt.Errorf("%s: %w", result.source.Location, result.err))
			if _, err := fmt.Fprintf(f.writer, "    ❌ %s: %v\n", result.source.Location, result.err); err != nil {
				allErrors = append(allErrors, errors.Wrap(err, "cannot write output"))
			}
		} else {
			allCRDs = append(allCRDs, result.crds...)
			successCount++
			crdCount += len(result.crds)
			if _, err := fmt.Fprintf(f.writer, "    ✅ %s: %d CRDs\n", result.source.Location, len(result.crds)); err != nil {
				allErrors = append(allErrors, errors.Wrap(err, "cannot write output"))
			}
		}
	}

	if _, err := fmt.Fprintf(f.writer, "\n[✓] Prefetched %d CRDs from %d/%d sources\n", crdCount, successCount, len(sources)); err != nil {
		allErrors = append(allErrors, errors.Wrap(err, "cannot write output"))
	}

	return allCRDs, allErrors
}

// prefetchAllFromSource fetches ALL CRDs from a single source (not just required ones).
func (f *CRDSourceFetcher) prefetchAllFromSource(ctx context.Context, source CRDSource) ([]*extv1.CustomResourceDefinition, error) {
	switch source.Type {
	case CRDSourceTypeGitHub:
		return f.prefetchAllFromGitHub(ctx, source)
	case CRDSourceTypeLocal:
		return f.prefetchAllFromLocal(source)
	case CRDSourceTypeK8sSchemas:
		return f.prefetchAllK8sSchemas(ctx, source)
	default:
		// For other types (catalog, cluster), we can't enumerate all CRDs
		return nil, fmt.Errorf("prefetch-all not supported for source type: %s", source.Type)
	}
}

// prefetchAllFromGitHub downloads ALL CRDs from a GitHub repository using the GitHub API.
func (f *CRDSourceFetcher) prefetchAllFromGitHub(ctx context.Context, source CRDSource) ([]*extv1.CustomResourceDefinition, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("github-%s-%s", strings.ReplaceAll(source.Location, "/", "-"), source.Branch)
	cachePath := filepath.Join(f.cacheDir, "crd-sources", cacheKey)

	// If cache exists, load from it
	if info, err := os.Stat(cachePath); err == nil && info.IsDir() {
		return f.loadAllFromCache(cachePath)
	}

	// Use Git Trees API instead of Contents API to handle directories with 1000+ files
	// The Contents API has a hard limit of 1000 items per directory
	// First, get the tree SHA for the branch
	refURL := fmt.Sprintf("https://api.github.com/repos/%s/git/ref/heads/%s",
		source.Location, source.Branch)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, refURL, nil)
	if err != nil {
		return nil, err
	}
	f.addGitHubHeaders(req)

	resp, err := httpDoWithRetry(ctx, f.httpClient, req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed for %s: %w", refURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d for %s", resp.StatusCode, refURL)
	}

	var refData struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refData); err != nil {
		return nil, fmt.Errorf("failed to decode ref response: %w", err)
	}

	// Now get the full tree recursively
	treeURL := fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s?recursive=1",
		source.Location, refData.Object.SHA)

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, treeURL, nil)
	if err != nil {
		return nil, err
	}
	f.addGitHubHeaders(req2)

	resp2, err := httpDoWithRetry(ctx, f.httpClient, req2)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed for tree: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d for tree", resp2.StatusCode)
	}

	var treeData struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&treeData); err != nil {
		return nil, fmt.Errorf("failed to decode tree response: %w", err)
	}

	if treeData.Truncated {
		if _, err := fmt.Fprintf(f.writer, "    ⚠️ Tree was truncated - repo may be very large\n"); err != nil {
			return nil, err
		}
	}

	// Filter YAML files in the target path
	var yamlFiles []struct {
		Name        string
		DownloadURL string
	}
	targetPath := source.Path
	if !strings.HasSuffix(targetPath, "/") {
		targetPath += "/"
	}
	for _, item := range treeData.Tree {
		if item.Type == "blob" && strings.HasPrefix(item.Path, source.Path) {
			filename := filepath.Base(item.Path)
			if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
				downloadURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s",
					source.Location, source.Branch, item.Path)
				yamlFiles = append(yamlFiles, struct {
					Name        string
					DownloadURL string
				}{Name: filename, DownloadURL: downloadURL})
			}
		}
	}

	// Download CRDs in parallel with error collection
	// Use fetchCRDsFromURL to handle multi-document YAML files (like crds.yml with multiple CRDs)
	type crdResult struct {
		crds []*extv1.CustomResourceDefinition
		err  error
		url  string
	}

	crdResults := make(chan crdResult, len(yamlFiles))
	sem := make(chan struct{}, f.parallelism)
	var wg sync.WaitGroup

	for _, file := range yamlFiles {
		wg.Add(1)
		go func(name, downloadURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fetchedCRDs, err := f.fetchCRDsFromURL(ctx, downloadURL)
			if err != nil {
				crdResults <- crdResult{err: err, url: downloadURL}
				return
			}

			// Save each valid CRD to cache
			var validCRDs []*extv1.CustomResourceDefinition
			for i, crd := range fetchedCRDs {
				if crd != nil && crd.Kind == "CustomResourceDefinition" {
					// Use index in filename for multi-doc files
					cacheName := name
					if len(fetchedCRDs) > 1 {
						cacheName = fmt.Sprintf("%s-%d", strings.TrimSuffix(name, filepath.Ext(name)), i) + filepath.Ext(name)
					}
					f.saveCRDToCache(cachePath, cacheName, crd)
					validCRDs = append(validCRDs, crd)
				}
			}
			crdResults <- crdResult{crds: validCRDs}
		}(file.Name, file.DownloadURL)
	}

	go func() {
		wg.Wait()
		close(crdResults)
	}()

	// Collect results
	var crds []*extv1.CustomResourceDefinition
	var fetchErrors []string
	for result := range crdResults {
		if result.err != nil {
			fetchErrors = append(fetchErrors, fmt.Sprintf("%s: %v", result.url, result.err))
		} else if len(result.crds) > 0 {
			crds = append(crds, result.crds...)
		}
	}

	// Report errors but don't fail (we still got some CRDs)
	if len(fetchErrors) > 0 && len(fetchErrors) < len(yamlFiles) {
		// Only warn if some files failed, not all
		// If all failed, the caller will see 0 CRDs
	}

	return crds, nil
}

// prefetchAllFromLocal loads ALL CRDs from a local directory.
func (f *CRDSourceFetcher) prefetchAllFromLocal(source CRDSource) ([]*extv1.CustomResourceDefinition, error) {
	var crds []*extv1.CustomResourceDefinition

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}

		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil // Skip unreadable files
		}

		var crd extv1.CustomResourceDefinition
		if err := yaml.Unmarshal(data, &crd); err != nil {
			return nil // Skip non-CRD files
		}

		if crd.Kind == "CustomResourceDefinition" {
			crds = append(crds, &crd)
		}

		return nil
	})

	return crds, err
}

// prefetchAllK8sSchemas downloads ALL known K8s core type schemas.
func (f *CRDSourceFetcher) prefetchAllK8sSchemas(ctx context.Context, source CRDSource) ([]*extv1.CustomResourceDefinition, error) {
	k8sVersion := source.Location
	if k8sVersion == "" {
		k8sVersion = "v1.29.0"
	}

	// Download all known K8s types in parallel
	type schemaResult struct {
		crd *extv1.CustomResourceDefinition
		err error
		gvk string
	}

	results := make(chan schemaResult, len(CoreK8sTypes))
	sem := make(chan struct{}, f.parallelism)
	var wg sync.WaitGroup

	for gvk, coreType := range CoreK8sTypes {
		wg.Add(1)
		go func(gvkStr string, ct struct {
			Group   string
			Version string
			Kind    string
		}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			kindLower := strings.ToLower(ct.Kind)
			url := fmt.Sprintf("https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/%s/%s.json",
				k8sVersion, kindLower)

			crd, err := f.fetchJSONSchemaAsCRD(ctx, url, ct.Group, ct.Version, ct.Kind)
			results <- schemaResult{crd: crd, err: err, gvk: gvkStr}
		}(gvk, coreType)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Create cache directory for k8s schemas
	cacheKey := fmt.Sprintf("k8s-%s", k8sVersion)
	cachePath := filepath.Join(f.cacheDir, "crd-sources", cacheKey)

	var crds []*extv1.CustomResourceDefinition
	for result := range results {
		if result.err == nil && result.crd != nil {
			crds = append(crds, result.crd)
			// Save to cache for later use
			filename := fmt.Sprintf("%s.yaml", strings.ToLower(result.crd.Spec.Names.Kind))
			f.saveCRDToCache(cachePath, filename, result.crd)
		}
		// Silently skip errors for individual schemas
	}

	return crds, nil
}

// loadAllFromCache loads ALL CRDs from a cache directory (for prefetch).
func (f *CRDSourceFetcher) loadAllFromCache(cachePath string) ([]*extv1.CustomResourceDefinition, error) {
	var crds []*extv1.CustomResourceDefinition

	err := filepath.Walk(cachePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil
		}

		var crd extv1.CustomResourceDefinition
		if err := yaml.Unmarshal(data, &crd); err != nil {
			return nil
		}

		if crd.Kind == "CustomResourceDefinition" {
			crds = append(crds, &crd)
		}

		return nil
	})

	return crds, err
}

// FetchFromSources fetches CRDs from multiple sources for the required GVKs.
// Uses parallel fetching to speed up the process.
func (f *CRDSourceFetcher) FetchFromSources(ctx context.Context, sources []CRDSource, requiredGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, error) {
	if _, err := fmt.Fprintf(f.writer, "\n=== CRD Source Discovery ===\n"); err != nil {
		return nil, errors.Wrap(err, "cannot write output")
	}
	if _, err := fmt.Fprintf(f.writer, "Looking for %d required CRDs from %d sources (parallel=%d)...\n\n", len(requiredGVKs), len(sources), f.parallelism); err != nil {
		return nil, errors.Wrap(err, "cannot write output")
	}

	// Use parallel fetching for all sources
	type fetchResult struct {
		source CRDSource
		crds   []*extv1.CustomResourceDefinition
		err    error
	}

	results := make(chan fetchResult, len(sources))
	sem := make(chan struct{}, f.parallelism)
	var wg sync.WaitGroup

	// Create a copy of requiredGVKs for thread-safe checking
	// Each goroutine will work with its own foundGVKs map
	for _, source := range sources {
		wg.Add(1)
		go func(src CRDSource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Each goroutine gets its own foundGVKs map for thread safety
			localFoundGVKs := make(map[string]bool)
			crds, err := f.fetchFromSource(ctx, src, requiredGVKs, localFoundGVKs)
			results <- fetchResult{source: src, crds: crds, err: err}
		}(source)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and merge found GVKs
	var allCRDs []*extv1.CustomResourceDefinition
	foundGVKs := make(map[string]bool)
	var fetchErrors []string

	for result := range results {
		if result.err != nil {
			fetchErrors = append(fetchErrors, fmt.Sprintf("%s: %v", result.source.Location, result.err))
			if _, err := fmt.Fprintf(f.writer, "    ⚠️  %s: %v\n", result.source.Location, result.err); err != nil {
				return nil, errors.Wrap(err, "cannot write output")
			}
		} else if len(result.crds) > 0 {
			// Deduplicate CRDs based on GVK
			for _, crd := range result.crds {
				for _, version := range crd.Spec.Versions {
					gvk := fmt.Sprintf("%s/%s, Kind=%s", crd.Spec.Group, version.Name, crd.Spec.Names.Kind)
					if !foundGVKs[gvk] {
						foundGVKs[gvk] = true
						allCRDs = append(allCRDs, crd)
					}
				}
			}
			if _, err := fmt.Fprintf(f.writer, "    ✅ %s: %d CRDs\n", result.source.Location, len(result.crds)); err != nil {
				return nil, errors.Wrap(err, "cannot write output")
			}
		}
	}

	// Report missing GVKs
	var missingGVKs []string
	for gvk := range requiredGVKs {
		if !foundGVKs[gvk] {
			missingGVKs = append(missingGVKs, gvk)
		}
	}

	if len(missingGVKs) > 0 {
		if _, err := fmt.Fprintf(f.writer, "\n[!] %d required CRDs not found in any source:\n", len(missingGVKs)); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}
		for _, gvk := range missingGVKs {
			if _, err := fmt.Fprintf(f.writer, "    ❌ %s\n", gvk); err != nil {
				return nil, errors.Wrap(err, "cannot write output")
			}
		}
		if _, err := fmt.Fprintf(f.writer, "\n"); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}
	}

	// Report found CRDs
	if len(foundGVKs) > 0 {
		if _, err := fmt.Fprintf(f.writer, "[✓] Found %d/%d required CRDs from sources\n", len(foundGVKs), len(requiredGVKs)); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}
	}

	return allCRDs, nil
}

// GetMissingGVKs returns GVKs that were not found in any source.
func (f *CRDSourceFetcher) GetMissingGVKs(requiredGVKs, foundGVKs map[string]bool) []string {
	var missing []string
	for gvk := range requiredGVKs {
		if !foundGVKs[gvk] {
			missing = append(missing, gvk)
		}
	}
	return missing
}

func (f *CRDSourceFetcher) fetchFromSource(ctx context.Context, source CRDSource, requiredGVKs, foundGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, error) {
	switch source.Type {
	case CRDSourceTypeGitHub:
		return f.fetchFromGitHub(ctx, source, requiredGVKs, foundGVKs)
	case CRDSourceTypeCatalog:
		return f.fetchFromCatalog(ctx, source, requiredGVKs, foundGVKs)
	case CRDSourceTypeLocal:
		return f.fetchFromLocal(source, requiredGVKs, foundGVKs)
	case CRDSourceTypeK8sSchemas:
		return f.fetchFromK8sSchemas(ctx, source, requiredGVKs, foundGVKs)
	default:
		return nil, fmt.Errorf("unknown source type: %s", source.Type)
	}
}

// fetchFromGitHub fetches CRDs from a GitHub repository.
func (f *CRDSourceFetcher) fetchFromGitHub(ctx context.Context, source CRDSource, requiredGVKs, foundGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("github-%s-%s", strings.ReplaceAll(source.Location, "/", "-"), source.Branch)
	cachePath := filepath.Join(f.cacheDir, "crd-sources", cacheKey)

	if crds, ok := f.loadFromCache(cachePath, requiredGVKs, foundGVKs); ok {
		if _, err := fmt.Fprintf(f.writer, "Loaded CRDs from cache: %s\n", source.Location); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}
		return crds, nil
	}

	if _, err := fmt.Fprintf(f.writer, "Fetching CRDs from GitHub: %s...\n", source.Location); err != nil {
		return nil, errors.Wrap(err, "cannot write output")
	}

	// For now, use raw file URLs for each CRD we need
	// This is more efficient than downloading the entire repo
	// Alternative: download archive from https://github.com/{repo}/archive/refs/heads/{branch}.tar.gz
	var crds []*extv1.CustomResourceDefinition

	for gvk := range requiredGVKs {
		if foundGVKs[gvk] {
			continue
		}

		// Parse GVK: "group/version, Kind=Kind"
		parts := strings.Split(gvk, ", Kind=")
		if len(parts) != 2 {
			continue
		}
		groupVersion := parts[0]
		kind := parts[1]

		gvParts := strings.Split(groupVersion, "/")
		if len(gvParts) != 2 {
			continue
		}
		group := gvParts[0]
		// version := gvParts[1]

		// Try to find the CRD file
		// Upbound providers use: group_kinds.yaml (plural)
		kindLower := strings.ToLower(kind)
		possibleNames := []string{
			fmt.Sprintf("%s_%ss.yaml", group, kindLower),          // e.g., ec2.aws.upbound.io_subnets.yaml
			fmt.Sprintf("%s_%s.yaml", group, kindLower),           // e.g., nats.deinstapel.de_natsaccount.yaml
			fmt.Sprintf("%s_%sies.yaml", group, kindLower[:len(kindLower)-1]), // e.g., policies -> policy
		}

		var lastErr error
		var triedURLs []string
		found := false
		for _, name := range possibleNames {
			rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", 
				source.Location, source.Branch, source.Path, name)
			triedURLs = append(triedURLs, name)

			crd, err := f.fetchCRDFromURL(ctx, rawURL)
			if err != nil {
				lastErr = err
				continue
			}
			if crd == nil {
				continue
			}
			// Verify this is the right CRD
			if crd.Spec.Group == group && crd.Spec.Names.Kind == kind {
				crds = append(crds, crd)
				foundGVKs[gvk] = true
				found = true
				
				// Cache the CRD
				f.saveCRDToCache(cachePath, name, crd)
				break
			}
		}
		// Log if we couldn't find the CRD after trying all patterns
		if !found && lastErr != nil {
			fmt.Fprintf(f.writer, "    ⚠️ Could not fetch %s from %s (tried: %v): %v\n", 
				gvk, source.Location, triedURLs, lastErr)
		}
	}

	return crds, nil
}

// fetchFromCatalog fetches CRDs from the Datree CRDs catalog.
func (f *CRDSourceFetcher) fetchFromCatalog(ctx context.Context, source CRDSource, requiredGVKs, foundGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, error) {
	if _, err := fmt.Fprintf(f.writer, "Fetching CRDs from catalog...\n"); err != nil {
		return nil, errors.Wrap(err, "cannot write output")
	}

	var crds []*extv1.CustomResourceDefinition

	for gvk := range requiredGVKs {
		if foundGVKs[gvk] {
			continue
		}

		// Parse GVK: "group/version, Kind=Kind" or "version, Kind=Kind" (for core K8s)
		parts := strings.SplitN(gvk, ", Kind=", 2)
		if len(parts) != 2 {
			continue
		}
		groupVersion := parts[0]
		kind := parts[1]
		kindLower := strings.ToLower(kind)

		gvParts := strings.Split(groupVersion, "/")

		var urls []string
		if len(gvParts) == 1 {
			// Core K8s type: "v1" -> try kubernetes/{kind}.json
			urls = []string{
				fmt.Sprintf("%s/kubernetes/%s.json", source.Location, kindLower),
			}
		} else if len(gvParts) == 2 {
			group := gvParts[0]
			version := gvParts[1]
			// Standard CRD format: {group}/{kind}_{version}.json
			urls = []string{
				fmt.Sprintf("%s/%s/%s_%s.json", source.Location, group, kindLower, version),
			}
		} else {
			continue
		}

		// Try each URL until one works
		var lastErr error
		found := false
		for _, url := range urls {
			crd, err := f.fetchCRDFromURL(ctx, url)
			if err != nil {
				lastErr = err
				continue
			}
			if crd != nil {
				crds = append(crds, crd)
				foundGVKs[gvk] = true
				found = true
				break
			}
		}
		// Log if we couldn't find the CRD from catalog
		if !found && lastErr != nil {
			fmt.Fprintf(f.writer, "    ⚠️ Could not fetch %s from catalog: %v\n", gvk, lastErr)
		}
	}

	return crds, nil
}

// fetchFromLocal loads CRDs from a local directory.
func (f *CRDSourceFetcher) fetchFromLocal(source CRDSource, requiredGVKs, foundGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, error) {
	if _, err := fmt.Fprintf(f.writer, "Loading CRDs from local path: %s\n", source.Location); err != nil {
		return nil, errors.Wrap(err, "cannot write output")
	}

	var crds []*extv1.CustomResourceDefinition

	err := filepath.Walk(source.Location, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}

		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil // Skip unreadable files
		}

		var crd extv1.CustomResourceDefinition
		if err := yaml.Unmarshal(data, &crd); err != nil {
			return nil // Skip non-CRD files
		}

		if crd.Kind != "CustomResourceDefinition" {
			return nil
		}

		// Check if this CRD is needed
		for _, version := range crd.Spec.Versions {
			gvk := fmt.Sprintf("%s/%s, Kind=%s", crd.Spec.Group, version.Name, crd.Spec.Names.Kind)
			if requiredGVKs[gvk] && !foundGVKs[gvk] {
				crds = append(crds, &crd)
				foundGVKs[gvk] = true
			}
		}

		return nil
	})

	return crds, err
}

func (f *CRDSourceFetcher) fetchCRDFromURL(ctx context.Context, url string) (*extv1.CustomResourceDefinition, error) {
	crds, err := f.fetchCRDsFromURL(ctx, url)
	if err != nil {
		return nil, err
	}
	if len(crds) == 0 {
		return nil, fmt.Errorf("no CRDs found in %s", url)
	}
	return crds[0], nil
}

// fetchCRDsFromURL fetches CRDs from a URL, handling multi-document YAML files.
// For private GitHub repos, it converts raw.githubusercontent.com URLs to GitHub API calls.
func (f *CRDSourceFetcher) fetchCRDsFromURL(ctx context.Context, url string) ([]*extv1.CustomResourceDefinition, error) {
	// For private repos, raw.githubusercontent.com doesn't work with tokens
	// Convert to GitHub API: https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}
	if strings.Contains(url, "raw.githubusercontent.com") && f.githubToken != "" {
		apiURL, err := convertRawURLToAPI(url)
		if err == nil {
			return f.fetchCRDsFromGitHubAPI(ctx, apiURL)
		}
		// If conversion fails, fall through to regular fetch
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Use retry logic to handle transient errors (5xx, timeouts, etc.)
	resp, err := httpDoWithRetry(ctx, f.httpClient, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRD from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle multi-document YAML files (separated by ---)
	var crds []*extv1.CustomResourceDefinition
	docs := strings.Split(string(data), "\n---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var crd extv1.CustomResourceDefinition
		if err := yaml.Unmarshal([]byte(doc), &crd); err != nil {
			continue // Skip non-CRD documents
		}
		// Only include valid CRDs (must have a name and kind)
		if crd.Name != "" && crd.Spec.Names.Kind != "" {
			crds = append(crds, &crd)
		}
	}

	return crds, nil
}

// convertRawURLToAPI converts a raw.githubusercontent.com URL to a GitHub API URL.
// Example: https://raw.githubusercontent.com/owner/repo/branch/path/file.yaml
// -> https://api.github.com/repos/owner/repo/contents/path/file.yaml?ref=branch
func convertRawURLToAPI(rawURL string) (string, error) {
	// Parse: https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
	prefix := "https://raw.githubusercontent.com/"
	if !strings.HasPrefix(rawURL, prefix) {
		return "", fmt.Errorf("not a raw GitHub URL")
	}
	
	rest := strings.TrimPrefix(rawURL, prefix)
	parts := strings.SplitN(rest, "/", 4) // owner, repo, branch, path
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid raw GitHub URL format")
	}
	
	owner := parts[0]
	repo := parts[1]
	branch := parts[2]
	path := parts[3]
	
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", 
		owner, repo, path, branch), nil
}

// fetchCRDsFromGitHubAPI fetches CRDs using the GitHub API (works with private repos).
func (f *CRDSourceFetcher) fetchCRDsFromGitHubAPI(ctx context.Context, apiURL string) ([]*extv1.CustomResourceDefinition, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	
	// Add GitHub auth headers
	f.addGitHubHeaders(req)
	
	resp, err := httpDoWithRetry(ctx, f.httpClient, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	
	// GitHub API returns JSON with content field (base64 encoded)
	var apiResp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub API response: %w", err)
	}
	
	if apiResp.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding: %s", apiResp.Encoding)
	}
	
	// Decode base64 content
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(apiResp.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 content: %w", err)
	}
	
	// Parse YAML (handle multi-document)
	var crds []*extv1.CustomResourceDefinition
	docs := strings.Split(string(data), "\n---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var crd extv1.CustomResourceDefinition
		if err := yaml.Unmarshal([]byte(doc), &crd); err != nil {
			continue // Skip non-CRD documents
		}
		if crd.Name != "" && crd.Spec.Names.Kind != "" {
			crds = append(crds, &crd)
		}
	}
	
	return crds, nil
}

// fetchFromK8sSchemas fetches core K8s JSON schemas from yannh/kubernetes-json-schema
// and converts them to CRD format for validation.
func (f *CRDSourceFetcher) fetchFromK8sSchemas(ctx context.Context, source CRDSource, requiredGVKs, foundGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, error) {
	k8sVersion := source.Location // e.g., "v1.29.0"
	if k8sVersion == "" {
		k8sVersion = "v1.29.0" // default
	}

	// Check cache first
	cacheKey := fmt.Sprintf("k8s-%s", k8sVersion)
	cachePath := filepath.Join(f.cacheDir, "crd-sources", cacheKey)

	if crds, ok := f.loadK8sFromCache(cachePath, requiredGVKs, foundGVKs); ok {
		if _, err := fmt.Fprintf(f.writer, "Loaded K8s schemas from cache: %s\n", k8sVersion); err != nil {
			return nil, errors.Wrap(err, "cannot write output")
		}
		return crds, nil
	}

	if _, err := fmt.Fprintf(f.writer, "Fetching K8s schemas from kubernetes-json-schema (%s)...\n", k8sVersion); err != nil {
		return nil, errors.Wrap(err, "cannot write output")
	}

	var crds []*extv1.CustomResourceDefinition

	for gvk := range requiredGVKs {
		if foundGVKs[gvk] {
			continue
		}

		coreType, ok := CoreK8sTypes[gvk]
		if !ok {
			continue // Not a core K8s type we know about
		}

		// Construct URL: https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/{version}/{kind}.json
		kindLower := strings.ToLower(coreType.Kind)
		url := fmt.Sprintf("https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/%s/%s.json", k8sVersion, kindLower)

		crd, err := f.fetchJSONSchemaAsCRD(ctx, url, coreType.Group, coreType.Version, coreType.Kind)
		if err == nil && crd != nil {
			crds = append(crds, crd)
			foundGVKs[gvk] = true
			// Save to cache
			filename := fmt.Sprintf("%s.yaml", kindLower)
			f.saveCRDToCache(cachePath, filename, crd)
		}
	}

	return crds, nil
}

// loadK8sFromCache loads K8s schemas from cache.
func (f *CRDSourceFetcher) loadK8sFromCache(cachePath string, requiredGVKs, foundGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, bool) {
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil, false
	}

	var crds []*extv1.CustomResourceDefinition
	foundAny := false

	for gvk := range requiredGVKs {
		if foundGVKs[gvk] {
			continue
		}

		coreType, ok := CoreK8sTypes[gvk]
		if !ok {
			continue // Not a core K8s type
		}

		// Try to load from cache
		kindLower := strings.ToLower(coreType.Kind)
		cacheFile := filepath.Join(cachePath, fmt.Sprintf("%s.yaml", kindLower))

		data, err := os.ReadFile(cacheFile)
		if err != nil {
			continue
		}

		var crd extv1.CustomResourceDefinition
		if err := yaml.Unmarshal(data, &crd); err != nil {
			continue
		}

		if crd.Kind == "CustomResourceDefinition" {
			crds = append(crds, &crd)
			foundGVKs[gvk] = true
			foundAny = true
		}
	}

	return crds, foundAny
}

// fetchJSONSchemaAsCRD fetches a JSON schema and converts it to a CRD for validation.
func (f *CRDSourceFetcher) fetchJSONSchemaAsCRD(ctx context.Context, url, group, version, kind string) (*extv1.CustomResourceDefinition, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse JSON schema
	var schema map[string]interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, err
	}

	// Convert JSON schema to OpenAPI v3 schema (they're similar)
	openAPISchema := convertJSONSchemaToOpenAPI(schema)

	// Create a synthetic CRD for validation
	crd := &extv1.CustomResourceDefinition{
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: group,
			Names: extv1.CustomResourceDefinitionNames{
				Kind:     kind,
				Singular: strings.ToLower(kind),
				Plural:   strings.ToLower(kind) + "s",
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:   version,
					Served: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: openAPISchema,
					},
				},
			},
		},
	}

	return crd, nil
}

// convertJSONSchemaToOpenAPI converts a JSON Schema to OpenAPI v3 schema format.
func convertJSONSchemaToOpenAPI(schema map[string]interface{}) *extv1.JSONSchemaProps {
	result := &extv1.JSONSchemaProps{}

	if desc, ok := schema["description"].(string); ok {
		result.Description = desc
	}

	// Handle type (JSON Schema allows arrays like ["string", "null"])
	if t, ok := schema["type"]; ok {
		switch v := t.(type) {
		case string:
			result.Type = v
		case []interface{}:
			// Take the first non-null type
			for _, item := range v {
				if s, ok := item.(string); ok && s != "null" {
					result.Type = s
					break
				}
			}
		}
	}

	if props, ok := schema["properties"].(map[string]interface{}); ok {
		result.Properties = make(map[string]extv1.JSONSchemaProps)
		for name, propSchema := range props {
			if propMap, ok := propSchema.(map[string]interface{}); ok {
				result.Properties[name] = *convertJSONSchemaToOpenAPI(propMap)
			}
		}
	}

	if items, ok := schema["items"].(map[string]interface{}); ok {
		converted := convertJSONSchemaToOpenAPI(items)
		result.Items = &extv1.JSONSchemaPropsOrArray{Schema: converted}
	}

	if additionalProps, ok := schema["additionalProperties"].(map[string]interface{}); ok {
		converted := convertJSONSchemaToOpenAPI(additionalProps)
		result.AdditionalProperties = &extv1.JSONSchemaPropsOrBool{Schema: converted}
	}

	if required, ok := schema["required"].([]interface{}); ok {
		for _, r := range required {
			if s, ok := r.(string); ok {
				result.Required = append(result.Required, s)
			}
		}
	}

	return result
}

func (f *CRDSourceFetcher) loadFromCache(cachePath string, requiredGVKs, foundGVKs map[string]bool) ([]*extv1.CustomResourceDefinition, bool) {
	info, err := os.Stat(cachePath)
	if err != nil || !info.IsDir() {
		return nil, false
	}

	// Cache is valid indefinitely until explicitly cleaned with --clean-crd-cache
	var crds []*extv1.CustomResourceDefinition

	err = filepath.Walk(cachePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil
		}

		var crd extv1.CustomResourceDefinition
		if err := yaml.Unmarshal(data, &crd); err != nil {
			return nil
		}

		// Check if this CRD is needed
		for _, version := range crd.Spec.Versions {
			gvk := fmt.Sprintf("%s/%s, Kind=%s", crd.Spec.Group, version.Name, crd.Spec.Names.Kind)
			if requiredGVKs[gvk] && !foundGVKs[gvk] {
				crds = append(crds, &crd)
				foundGVKs[gvk] = true
			}
		}

		return nil
	})

	if err != nil {
		return nil, false
	}

	return crds, len(crds) > 0
}

func (f *CRDSourceFetcher) saveCRDToCache(cachePath, filename string, crd *extv1.CustomResourceDefinition) error {
	if err := os.MkdirAll(cachePath, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(crd)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(cachePath, filename), data, 0644)
}

// ParseCRDSources parses a list of CRD source specifications.
// Formats supported:
//   - Well-known names: "upjet-aws", "upjet-azure", "nats-operator", "datree-catalog"
//   - GitHub URLs: "https://github.com/crossplane-contrib/provider-upjet-aws"
//   - GitHub URLs with path: "https://github.com/owner/repo#branch:path/to/crds"
//   - Explicit format: "github:owner/repo:branch:path"
//   - Local paths: "local:/path/to/crds" or "/path/to/crds"
//   - Catalog URL: "catalog:https://..."
func ParseCRDSources(specs []string) ([]CRDSource, error) {
	var sources []CRDSource

	for _, spec := range specs {
		source, err := parseSingleSource(spec)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}

	return sources, nil
}

func parseSingleSource(spec string) (CRDSource, error) {
	// Check for cluster source
	if spec == "cluster" {
		return CRDSource{Type: CRDSourceTypeCluster}, nil
	}

	// Check if it's a GitHub URL (https://github.com/...)
	if strings.HasPrefix(spec, "https://github.com/") {
		return parseGitHubURL(spec)
	}

	// Check if it's a local path (starts with / or ./)
	if strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		return CRDSource{
			Type:     CRDSourceTypeLocal,
			Location: spec,
		}, nil
	}

	// Parse explicit format: type:location
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) < 2 {
		return CRDSource{}, fmt.Errorf("invalid CRD source: %s\nSupported formats:\n"+
			"  - GitHub URL: https://github.com/owner/repo\n"+
			"  - GitHub URL with path: https://github.com/owner/repo#branch:path/to/crds\n"+
			"  - Explicit: github:owner/repo:branch:path\n"+
			"  - Catalog: catalog:https://raw.githubusercontent.com/datreeio/CRDs-catalog/main\n"+
			"  - K8s core schemas: k8s:v1.29.0\n"+
			"  - Cluster: cluster\n"+
			"  - Local: /path/to/crds or local:/path/to/crds", spec)
	}

	sourceTypeStr := parts[0]
	location := parts[1]

	switch sourceTypeStr {
	case "github":
		// Format: github:owner/repo:branch:path
		githubParts := strings.SplitN(location, ":", 3)
		if len(githubParts) < 1 {
			return CRDSource{}, fmt.Errorf("invalid GitHub source: %s", spec)
		}
		source := CRDSource{
			Type:     CRDSourceTypeGitHub,
			Location: githubParts[0],
			Branch:   "main",
			Path:     "package/crds",
		}
		if len(githubParts) > 1 {
			source.Branch = githubParts[1]
		}
		if len(githubParts) > 2 {
			source.Path = githubParts[2]
		}
		return source, nil

	case "local":
		return CRDSource{
			Type:     CRDSourceTypeLocal,
			Location: location,
		}, nil

	case "catalog":
		return CRDSource{
			Type:     CRDSourceTypeCatalog,
			Location: location,
		}, nil

	case "k8s":
		return CRDSource{
			Type:     CRDSourceTypeK8sSchemas,
			Location: location, // K8s version like "v1.29.0"
		}, nil

	default:
		return CRDSource{}, fmt.Errorf("unknown CRD source type: %s", sourceTypeStr)
	}
}

// parseGitHubURL parses a GitHub URL into a CRDSource.
// Formats:
//   - https://github.com/owner/repo
//   - https://github.com/owner/repo#branch
//   - https://github.com/owner/repo#branch:path/to/crds
func parseGitHubURL(url string) (CRDSource, error) {
	// Remove https://github.com/ prefix
	path := strings.TrimPrefix(url, "https://github.com/")
	
	source := CRDSource{
		Type:   CRDSourceTypeGitHub,
		Branch: "main",
		Path:   "package/crds", // Default for Upbound providers
	}

	// Check for #branch:path suffix
	if idx := strings.Index(path, "#"); idx != -1 {
		extra := path[idx+1:]
		path = path[:idx]

		// Parse branch:path
		if colonIdx := strings.Index(extra, ":"); colonIdx != -1 {
			source.Branch = extra[:colonIdx]
			source.Path = extra[colonIdx+1:]
		} else {
			source.Branch = extra
		}
	}

	// Extract owner/repo
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return CRDSource{}, fmt.Errorf("invalid GitHub URL: %s (expected https://github.com/owner/repo)", url)
	}
	source.Location = parts[0] + "/" + parts[1]

	// Auto-detect path for known patterns
	if source.Path == "package/crds" {
		// Check if this looks like a kubebuilder project (config/crd/bases)
		if strings.Contains(strings.ToLower(source.Location), "operator") {
			source.Path = "config/crd/bases"
		}
	}

	return source, nil
}
