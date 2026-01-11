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
	"fmt"
	"io"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
)

// ProviderMapping maps API groups to provider packages.
// Use exact semver versions (not constraints) that exist in the registry.
var ProviderMapping = map[string]string{
	// AWS Upbound Providers (family providers)
	"ec2.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-ec2:v1.14.0",
	"iam.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-iam:v1.14.0",
	"s3.aws.upbound.io":               "xpkg.upbound.io/upbound/provider-aws-s3:v1.14.0",
	"eks.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-eks:v1.14.0",
	"sqs.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-sqs:v1.14.0",
	"rds.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-rds:v1.14.0",
	"kms.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-kms:v1.14.0",
	"cloudwatchevents.aws.upbound.io": "xpkg.upbound.io/upbound/provider-aws-cloudwatchevents:v1.14.0",
	"cloudwatchlogs.aws.upbound.io":   "xpkg.upbound.io/upbound/provider-aws-cloudwatchlogs:v1.14.0",
	"lambda.aws.upbound.io":           "xpkg.upbound.io/upbound/provider-aws-lambda:v1.14.0",
	"sns.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-sns:v1.14.0",
	"route53.aws.upbound.io":          "xpkg.upbound.io/upbound/provider-aws-route53:v1.14.0",
	"acm.aws.upbound.io":              "xpkg.upbound.io/upbound/provider-aws-acm:v1.14.0",
	"elasticache.aws.upbound.io":      "xpkg.upbound.io/upbound/provider-aws-elasticache:v1.14.0",
	"secretsmanager.aws.upbound.io":   "xpkg.upbound.io/upbound/provider-aws-secretsmanager:v1.14.0",

	// Azure Upbound Providers (family providers)
	"network.azure.upbound.io":          "xpkg.upbound.io/upbound/provider-azure-network:v1.4.0",
	"authorization.azure.upbound.io":    "xpkg.upbound.io/upbound/provider-azure-authorization:v1.4.0",
	"managedidentity.azure.upbound.io":  "xpkg.upbound.io/upbound/provider-azure-managedidentity:v1.4.0",
	"storage.azure.upbound.io":          "xpkg.upbound.io/upbound/provider-azure-storage:v1.4.0",
	"containerservice.azure.upbound.io": "xpkg.upbound.io/upbound/provider-azure-containerservice:v1.4.0",
	"keyvault.azure.upbound.io":         "xpkg.upbound.io/upbound/provider-azure-keyvault:v1.4.0",
	"dbforpostgresql.azure.upbound.io":  "xpkg.upbound.io/upbound/provider-azure-dbforpostgresql:v1.4.0",
	"dns.azure.upbound.io":              "xpkg.upbound.io/upbound/provider-azure-dns:v1.4.0",
	"compute.azure.upbound.io":          "xpkg.upbound.io/upbound/provider-azure-compute:v1.4.0",

	// Crossplane Contrib Providers
	"kubernetes.crossplane.io": "xpkg.upbound.io/crossplane-contrib/provider-kubernetes:v0.13.0",
	"helm.crossplane.io":       "xpkg.upbound.io/crossplane-contrib/provider-helm:v0.18.0",

	// Vault Providers
	"kubernetes.vault.upbound.io": "xpkg.upbound.io/upbound/provider-vault:v0.4.0",
	"auth.vault.upbound.io":       "xpkg.upbound.io/upbound/provider-vault:v0.4.0",

	// GCP Providers (for future use)
	"compute.gcp.upbound.io":   "xpkg.upbound.io/upbound/provider-gcp-compute:v1.4.0",
	"storage.gcp.upbound.io":   "xpkg.upbound.io/upbound/provider-gcp-storage:v1.4.0",
	"container.gcp.upbound.io": "xpkg.upbound.io/upbound/provider-gcp-container:v1.4.0",
}

// DiscoveredProvider represents a provider that was discovered from compositions.
type DiscoveredProvider struct {
	APIGroup     string
	Package      string
	UsageCount   int
	ResourceKinds []string
}

// ProviderDiscovery discovers which providers are needed based on composition resources.
type ProviderDiscovery struct {
	discoveredProviders map[string]*DiscoveredProvider
	unknownAPIGroups    map[string][]string // API group -> list of kinds
}

// NewProviderDiscovery creates a new ProviderDiscovery.
func NewProviderDiscovery() *ProviderDiscovery {
	return &ProviderDiscovery{
		discoveredProviders: make(map[string]*DiscoveredProvider),
		unknownAPIGroups:    make(map[string][]string),
	}
}

// DiscoverFromCompositions scans compositions and discovers required providers.
func (d *ProviderDiscovery) DiscoverFromCompositions(parser *CompositionParser) {
	for _, comp := range parser.GetCompositions() {
		for _, res := range comp.Resources {
			if res.Base == nil {
				continue
			}

			gvk := res.Base.GroupVersionKind()
			d.addResource(gvk)
		}
	}
}

// DiscoverFromUnstructured scans unstructured objects for base resources.
func (d *ProviderDiscovery) DiscoverFromUnstructured(objects []*unstructured.Unstructured) {
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

			input, ok := stepMap["input"].(map[string]interface{})
			if !ok {
				continue
			}

			resources, ok := input["resources"].([]interface{})
			if !ok {
				continue
			}

			for _, res := range resources {
				resMap, ok := res.(map[string]interface{})
				if !ok {
					continue
				}

				base, ok := resMap["base"].(map[string]interface{})
				if !ok {
					continue
				}

				apiVersion, _ := base["apiVersion"].(string)
				kind, _ := base["kind"].(string)

				if apiVersion != "" && kind != "" {
					gv := strings.Split(apiVersion, "/")
					var group string
					if len(gv) == 2 {
						group = gv[0]
					}

					gvk := schema.GroupVersionKind{
						Group:   group,
						Version: gv[len(gv)-1],
						Kind:    kind,
					}
					d.addResource(gvk)

					// Also extract nested resources from well-known paths
					d.extractNestedResources(base)
				}
			}
		}
	}
}

// extractNestedResources extracts API groups from nested resources inside base resources.
// For example, extracts karpenter.sh/v1 from inside kubernetes.crossplane.io Object's manifest.
func (d *ProviderDiscovery) extractNestedResources(base map[string]interface{}) {
	// Check well-known paths for nested resources
	nestedPaths := [][]string{
		{"spec", "forProvider", "manifest"},
		{"spec", "forProvider", "values"},
	}

	for _, pathParts := range nestedPaths {
		nested := base
		for _, part := range pathParts {
			next, ok := nested[part].(map[string]interface{})
			if !ok {
				nested = nil
				break
			}
			nested = next
		}

		if nested == nil {
			continue
		}

		// Check if nested has apiVersion and kind
		apiVersion, hasAPIVersion := nested["apiVersion"].(string)
		kind, hasKind := nested["kind"].(string)
		if !hasAPIVersion || !hasKind {
			continue
		}

		// Parse GVK
		gv := strings.Split(apiVersion, "/")
		var group string
		if len(gv) == 2 {
			group = gv[0]
		}

		if group != "" {
			gvk := schema.GroupVersionKind{
				Group:   group,
				Version: gv[len(gv)-1],
				Kind:    kind,
			}
			d.addResource(gvk)
		}
	}
}

func (d *ProviderDiscovery) addResource(gvk schema.GroupVersionKind) {
	group := gvk.Group

	// Skip core Kubernetes resources
	if group == "" || group == "v1" {
		return
	}

	// Look up provider package
	pkg, found := ProviderMapping[group]
	if !found {
		// Track ALL unknown API groups - we'll try to fetch their CRDs from cluster
		if _, exists := d.unknownAPIGroups[group]; !exists {
			d.unknownAPIGroups[group] = make([]string, 0)
		}
		// Add kind if not already present
		for _, k := range d.unknownAPIGroups[group] {
			if k == gvk.Kind {
				return
			}
		}
		d.unknownAPIGroups[group] = append(d.unknownAPIGroups[group], gvk.Kind)
		return
	}

	// Track discovered provider
	if _, exists := d.discoveredProviders[pkg]; !exists {
		d.discoveredProviders[pkg] = &DiscoveredProvider{
			APIGroup:      group,
			Package:       pkg,
			UsageCount:    0,
			ResourceKinds: make([]string, 0),
		}
	}

	d.discoveredProviders[pkg].UsageCount++

	// Add kind if not already present
	for _, k := range d.discoveredProviders[pkg].ResourceKinds {
		if k == gvk.Kind {
			return
		}
	}
	d.discoveredProviders[pkg].ResourceKinds = append(d.discoveredProviders[pkg].ResourceKinds, gvk.Kind)
}

// GetDiscoveredProviders returns the list of discovered provider packages.
func (d *ProviderDiscovery) GetDiscoveredProviders() []*DiscoveredProvider {
	result := make([]*DiscoveredProvider, 0, len(d.discoveredProviders))
	for _, p := range d.discoveredProviders {
		result = append(result, p)
	}
	return result
}

// GetProviderPackages returns just the package references.
func (d *ProviderDiscovery) GetProviderPackages() []string {
	result := make([]string, 0, len(d.discoveredProviders))
	for pkg := range d.discoveredProviders {
		result = append(result, pkg)
	}
	return result
}

// GetUnknownAPIGroups returns API groups that couldn't be mapped to providers.
func (d *ProviderDiscovery) GetUnknownAPIGroups() map[string][]string {
	return d.unknownAPIGroups
}

// GenerateProviderObjects generates Provider objects for discovered providers.
func (d *ProviderDiscovery) GenerateProviderObjects() []*unstructured.Unstructured {
	result := make([]*unstructured.Unstructured, 0, len(d.discoveredProviders))

	for _, provider := range d.discoveredProviders {
		// Generate a name from the package
		parts := strings.Split(provider.Package, "/")
		namePart := parts[len(parts)-1]
		namePart = strings.Split(namePart, ":")[0] // Remove version

		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "pkg.crossplane.io/v1",
				"kind":       "Provider",
				"metadata": map[string]interface{}{
					"name": namePart,
				},
				"spec": map[string]interface{}{
					"package": provider.Package,
				},
			},
		}
		result = append(result, obj)
	}

	return result
}

// PrintDiscoveryReport prints a report of discovered providers.
func (d *ProviderDiscovery) PrintDiscoveryReport(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "\n=== Provider Discovery ===\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if len(d.discoveredProviders) == 0 {
		if _, err := fmt.Fprintf(w, "No provider resources found in compositions.\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
		return nil
	}

	if _, err := fmt.Fprintf(w, "Discovered %d providers from compositions:\n", len(d.discoveredProviders)); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	for _, provider := range d.discoveredProviders {
		if _, err := fmt.Fprintf(w, "  - %s (%d resources: %s)\n",
			provider.Package, provider.UsageCount, strings.Join(provider.ResourceKinds, ", ")); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
	}

	if len(d.unknownAPIGroups) > 0 {
		if _, err := fmt.Fprintf(w, "\nUnknown API groups (no provider mapping):\n"); err != nil {
			return errors.Wrap(err, "cannot write output")
		}
		for group, kinds := range d.unknownAPIGroups {
			if _, err := fmt.Fprintf(w, "  - %s (%s)\n", group, strings.Join(kinds, ", ")); err != nil {
				return errors.Wrap(err, "cannot write output")
			}
		}
	}

	return nil
}
