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
	"strings"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// StatusWrite represents a patch that writes to the parent's status.
type StatusWrite struct {
	CompositionName string // Name of the composition doing the write
	ResourceName    string // Name of the resource within the composition
	FromFieldPath   string // Source path (from resource or composite)
	ToFieldPath     string // Destination path in parent status (e.g., "status.vpcId")
	SourceFile      string
	SourceLine      int
}

// StatusRead represents a patch that reads from a child XR's status.
type StatusRead struct {
	CompositionName string // Parent composition reading the status
	ResourceName    string // Resource (child XR) being read from
	ResourceGVK     schema.GroupVersionKind
	FromFieldPath   string // Path in child's status (e.g., "status.vpcId")
	ToFieldPath     string // Where it's written in parent
	SourceFile      string
	SourceLine      int
}

// StatusChain represents a complete propagation chain from source to final destination.
type StatusChain struct {
	SourceComposition string   // Where the chain starts
	SourcePath        string   // Original status field
	FinalPath         string   // Where it ends up
	Hops              []string // List of compositions in the chain
	Complete          bool     // Whether chain reaches root
}

// StatusChainIssue represents a problem in status propagation.
type StatusChainIssue struct {
	Severity        string // "error" or "warning"
	CompositionName string
	ResourceName    string
	StatusPath      string
	Message         string
	SourceFile      string
	SourceLine      int
}

// StatusChainValidator validates status field propagation through composition hierarchies.
type StatusChainValidator struct {
	compositions []*ParsedComposition
	schemas      *SchemaNavigator
	
	// Maps for quick lookups
	compositionsByXRKind map[string][]*ParsedComposition // XR Kind -> compositions that create it
	statusWrites         map[string][]StatusWrite        // CompositionName -> status writes
	statusReads          map[string][]StatusRead         // CompositionName -> reads from CHILD's status (ToCompositeFieldPath)
	internalStatusReads  map[string][]StatusRead         // CompositionName -> reads from OWN status (FromCompositeFieldPath)
}

// NewStatusChainValidator creates a new validator.
func NewStatusChainValidator(compositions []*ParsedComposition, crds []*extv1.CustomResourceDefinition) *StatusChainValidator {
	return &StatusChainValidator{
		compositions:         compositions,
		schemas:              NewSchemaNavigator(crds),
		compositionsByXRKind: make(map[string][]*ParsedComposition),
		statusWrites:         make(map[string][]StatusWrite),
		statusReads:          make(map[string][]StatusRead),
		internalStatusReads:  make(map[string][]StatusRead),
	}
}

// Validate performs all status chain validations.
func (v *StatusChainValidator) Validate() []StatusChainIssue {
	var issues []StatusChainIssue
	
	// Step 1: Build indexes
	v.buildIndexes()
	
	// Step 2: Validate each status write has proper XRD definition
	issues = append(issues, v.validateStatusWriteDefinitions()...)
	
	// Step 3: Validate status reads from child XRs
	issues = append(issues, v.validateStatusReads()...)
	
	// Step 4: Detect broken chains
	issues = append(issues, v.detectBrokenChains()...)
	
	// Step 5: Warn about unused status writes (optional - can be noisy)
	// issues = append(issues, v.detectUnusedStatusWrites()...)
	
	return issues
}

// buildIndexes extracts status writes and reads from all compositions.
func (v *StatusChainValidator) buildIndexes() {
	for _, comp := range v.compositions {
		// Map composition by the XR kind it creates
		if comp.CompositeTypeRef.Kind != "" {
			v.compositionsByXRKind[comp.CompositeTypeRef.Kind] = append(
				v.compositionsByXRKind[comp.CompositeTypeRef.Kind], comp)
		}
		
		// Extract status writes and reads from ALL patch types
		for _, patchInfo := range comp.AllPatches {
			patch := patchInfo.Patch
			
			// Determine the GVK of the resource (child XR or composed resource)
			var resourceGVK schema.GroupVersionKind
			for _, res := range comp.Resources {
				if res.Name == patchInfo.ResourceName {
					resourceGVK = res.BaseGVK
					break
				}
			}
			
			// Extract status writes (patches that write TO composite status)
			v.extractStatusWrites(comp, patchInfo, patch, resourceGVK)
			
			// Extract status reads (patches that read FROM composite status)
			v.extractStatusReads(comp, patchInfo, patch, resourceGVK)
		}
	}
}

// extractStatusWrites identifies all patches that write to the composite's status.
func (v *StatusChainValidator) extractStatusWrites(comp *ParsedComposition, patchInfo PatchInfo, patch Patch, resourceGVK schema.GroupVersionKind) {
	// Normalize patch type - empty defaults to FromCompositeFieldPath (which doesn't write to composite status)
	patchType := patch.Type
	
	// ToCompositeFieldPath: toFieldPath writes to composite
	if patchType == PatchTypeToCompositeFieldPath {
		if strings.HasPrefix(patch.ToFieldPath, "status.") || patch.ToFieldPath == "status" {
			v.statusWrites[comp.Name] = append(v.statusWrites[comp.Name], StatusWrite{
				CompositionName: comp.Name,
				ResourceName:    patchInfo.ResourceName,
				FromFieldPath:   patch.FromFieldPath,
				ToFieldPath:     patch.ToFieldPath,
				SourceFile:      comp.SourceFile,
				SourceLine:      comp.SourceLine,
			})
		}
	}
	
	// CombineToComposite: toFieldPath writes to composite
	if patchType == PatchTypeCombineToComposite {
		if strings.HasPrefix(patch.ToFieldPath, "status.") || patch.ToFieldPath == "status" {
			v.statusWrites[comp.Name] = append(v.statusWrites[comp.Name], StatusWrite{
				CompositionName: comp.Name,
				ResourceName:    patchInfo.ResourceName,
				FromFieldPath:   "", // Combine doesn't have single fromFieldPath
				ToFieldPath:     patch.ToFieldPath,
				SourceFile:      comp.SourceFile,
				SourceLine:      comp.SourceLine,
			})
		}
	}
}

// extractStatusReads identifies patches that read from CHILD RESOURCES' status.
// This is used to validate that child XRs actually provide the status fields that parents expect.
//
// IMPORTANT DISTINCTION:
// - FromCompositeFieldPath with fromFieldPath: status.* = reads from COMPOSITE's OWN status (internal usage)
// - ToCompositeFieldPath with fromFieldPath: status.* = reads from CHILD RESOURCE's status (status chain)
//
// We capture BOTH types here, but for different purposes:
// - "internalStatusReads" = FromCompositeFieldPath reading from own status (for internal usage detection)
// - "childStatusReads" = ToCompositeFieldPath reading from child's status (for status chain validation)
func (v *StatusChainValidator) extractStatusReads(comp *ParsedComposition, patchInfo PatchInfo, patch Patch, resourceGVK schema.GroupVersionKind) {
	// Normalize patch type - empty defaults to FromCompositeFieldPath
	patchType := patch.Type
	if patchType == "" {
		patchType = PatchTypeFromCompositeFieldPath
	}
	
	// FromCompositeFieldPath (or default): reads from COMPOSITE's OWN status
	// This is for INTERNAL status usage detection (same composition reads its own status)
	if patchType == PatchTypeFromCompositeFieldPath {
		if strings.HasPrefix(patch.FromFieldPath, "status.") || patch.FromFieldPath == "status" {
			v.internalStatusReads[comp.Name] = append(v.internalStatusReads[comp.Name], StatusRead{
				CompositionName: comp.Name,
				ResourceName:    patchInfo.ResourceName,
				ResourceGVK:     resourceGVK,
				FromFieldPath:   patch.FromFieldPath,
				ToFieldPath:     patch.ToFieldPath,
				SourceFile:      comp.SourceFile,
				SourceLine:      comp.SourceLine,
			})
		}
	}
	
	// CombineFromComposite: reads from COMPOSITE's OWN status (internal usage)
	if patchType == PatchTypeCombineFromComposite {
		if patch.Combine != nil {
			for _, variable := range patch.Combine.Variables {
				if strings.HasPrefix(variable.FromFieldPath, "status.") || variable.FromFieldPath == "status" {
					v.internalStatusReads[comp.Name] = append(v.internalStatusReads[comp.Name], StatusRead{
						CompositionName: comp.Name,
						ResourceName:    patchInfo.ResourceName,
						ResourceGVK:     resourceGVK,
						FromFieldPath:   variable.FromFieldPath,
						ToFieldPath:     patch.ToFieldPath,
						SourceFile:      comp.SourceFile,
						SourceLine:      comp.SourceLine,
					})
				}
			}
		}
	}
	
	// ToCompositeFieldPath: reads from CHILD RESOURCE's status
	// This is for STATUS CHAIN validation (parent reads from child XR's status)
	if patchType == PatchTypeToCompositeFieldPath {
		if strings.HasPrefix(patch.FromFieldPath, "status.") || patch.FromFieldPath == "status" {
			v.statusReads[comp.Name] = append(v.statusReads[comp.Name], StatusRead{
				CompositionName: comp.Name,
				ResourceName:    patchInfo.ResourceName,
				ResourceGVK:     resourceGVK,
				FromFieldPath:   patch.FromFieldPath,
				ToFieldPath:     patch.ToFieldPath,
				SourceFile:      comp.SourceFile,
				SourceLine:      comp.SourceLine,
			})
		}
	}
	
	// CombineToComposite: reads from CHILD RESOURCE's status
	if patchType == PatchTypeCombineToComposite {
		if patch.Combine != nil {
			for _, variable := range patch.Combine.Variables {
				if strings.HasPrefix(variable.FromFieldPath, "status.") || variable.FromFieldPath == "status" {
					v.statusReads[comp.Name] = append(v.statusReads[comp.Name], StatusRead{
						CompositionName: comp.Name,
						ResourceName:    patchInfo.ResourceName,
						ResourceGVK:     resourceGVK,
						FromFieldPath:   variable.FromFieldPath,
						ToFieldPath:     patch.ToFieldPath,
						SourceFile:      comp.SourceFile,
						SourceLine:      comp.SourceLine,
					})
				}
			}
		}
	}
}

// validateStatusWriteDefinitions checks that status fields being written are defined in the XRD.
func (v *StatusChainValidator) validateStatusWriteDefinitions() []StatusChainIssue {
	var issues []StatusChainIssue
	
	for _, comp := range v.compositions {
		writes := v.statusWrites[comp.Name]
		if len(writes) == 0 {
			continue
		}
		
		// Check if XRD defines the status fields
		xrdGVK := comp.CompositeTypeRef
		if xrdGVK.Kind == "" {
			continue // No XRD reference, can't validate
		}
		
		for _, write := range writes {
			// Validate the toFieldPath exists in the XRD schema
			result := v.schemas.ValidatePath(xrdGVK, write.ToFieldPath)
			if !result.Valid {
				issues = append(issues, StatusChainIssue{
					Severity:        "error",
					CompositionName: comp.Name,
					ResourceName:    write.ResourceName,
					StatusPath:      write.ToFieldPath,
					Message: fmt.Sprintf(
						"composition '%s' writes to '%s' but XRD '%s' doesn't define this field (reason: %s)",
						comp.Name, write.ToFieldPath, xrdGVK.Kind, result.Reason),
					SourceFile: write.SourceFile,
					SourceLine: write.SourceLine,
				})
			}
		}
	}
	
	return issues
}

// validateStatusReads checks that parent compositions reading status from child XRs
// can actually get that data (child writes it and child XRD defines it).
func (v *StatusChainValidator) validateStatusReads() []StatusChainIssue {
	var issues []StatusChainIssue
	
	for _, comp := range v.compositions {
		reads := v.statusReads[comp.Name]
		if len(reads) == 0 {
			continue
		}
		
		for _, read := range reads {
			// Find the child XR's kind
			childKind := read.ResourceGVK.Kind
			if childKind == "" {
				continue // Can't validate without knowing the child type
			}
			
			// Find compositions that create this child XR kind
			childCompositions := v.compositionsByXRKind[childKind]
			if len(childCompositions) == 0 {
				// Child XR kind not found - this might be a provider resource, not an XR
				// Only validate if it looks like an XR (custom group)
				if !isProviderResource(read.ResourceGVK) {
					issues = append(issues, StatusChainIssue{
						Severity:        "warning",
						CompositionName: comp.Name,
						ResourceName:    read.ResourceName,
						StatusPath:      read.FromFieldPath,
						Message: fmt.Sprintf(
							"composition '%s' reads '%s' from child XR '%s', but no composition found for this XR kind",
							comp.Name, read.FromFieldPath, childKind),
						SourceFile: read.SourceFile,
						SourceLine: read.SourceLine,
					})
				}
				continue
			}
			
			// Check if ANY child composition writes to this status field
			foundWrite := false
			for _, childComp := range childCompositions {
				childWrites := v.statusWrites[childComp.Name]
				for _, write := range childWrites {
					if write.ToFieldPath == read.FromFieldPath {
						foundWrite = true
						break
					}
				}
				if foundWrite {
					break
				}
			}
			
			if !foundWrite {
				issues = append(issues, StatusChainIssue{
					Severity:        "error",
					CompositionName: comp.Name,
					ResourceName:    read.ResourceName,
					StatusPath:      read.FromFieldPath,
					Message: fmt.Sprintf(
						"composition '%s' reads '%s' from child XR '%s', but child composition never writes to this status field",
						comp.Name, read.FromFieldPath, childKind),
					SourceFile: read.SourceFile,
					SourceLine: read.SourceLine,
				})
			}
			
			// Also validate the child XRD defines this field
			for _, childComp := range childCompositions {
				childXRDGVK := childComp.CompositeTypeRef
				if childXRDGVK.Kind == "" {
					continue
				}
				
				result := v.schemas.ValidatePath(childXRDGVK, read.FromFieldPath)
				if !result.Valid {
					issues = append(issues, StatusChainIssue{
						Severity:        "error",
						CompositionName: comp.Name,
						ResourceName:    read.ResourceName,
						StatusPath:      read.FromFieldPath,
						Message: fmt.Sprintf(
							"composition '%s' reads '%s' from child XR '%s', but child XRD doesn't define this field (reason: %s)",
							comp.Name, read.FromFieldPath, childKind, result.Reason),
						SourceFile: read.SourceFile,
						SourceLine: read.SourceLine,
					})
					break // Only report once
				}
			}
		}
	}
	
	return issues
}

// detectBrokenChains identifies status fields that are written but never used anywhere.
func (v *StatusChainValidator) detectBrokenChains() []StatusChainIssue {
	var issues []StatusChainIssue
	
	// Group compositions by XR kind to handle provider-specific fields
	compsByKind := make(map[string][]*ParsedComposition)
	for _, comp := range v.compositions {
		if comp.CompositeTypeRef.Kind != "" {
			compsByKind[comp.CompositeTypeRef.Kind] = append(compsByKind[comp.CompositeTypeRef.Kind], comp)
		}
	}
	
	// For each XR kind, check status field usage across ALL compositions
	for xrKind, compositions := range compsByKind {
		// Collect all status fields written by ANY composition for this XR kind
		statusFieldsWritten := make(map[string][]string) // field -> []compositionName
		for _, comp := range compositions {
			writes := v.statusWrites[comp.Name]
			for _, write := range writes {
				statusFieldsWritten[write.ToFieldPath] = append(statusFieldsWritten[write.ToFieldPath], comp.Name)
			}
		}
		
		// For each written status field, check if it's used ANYWHERE
		for statusField, writingComps := range statusFieldsWritten {
			// Check 1: Is it read internally by the same composition?
			// A status field is "used internally" if the same composition that writes it
			// also has a FromCompositeFieldPath patch that reads from that status field.
			// (These are stored in internalStatusReads, NOT statusReads)
			usedInternally := false
			for _, compName := range writingComps {
				reads := v.internalStatusReads[compName]
				for _, read := range reads {
					// Internal read: any patch in this composition that reads from our own status
					// The FromFieldPath is the XR's status field path (e.g., "status.storageAccountName")
					if read.FromFieldPath == statusField {
						usedInternally = true
						break
					}
				}
				if usedInternally {
					break
				}
			}
			
			if usedInternally {
				continue // Used internally - not unused!
			}
			
			// Check 2: Is it read by ANY parent composition?
			readByParent := false
			for _, parentComp := range v.compositions {
				// Check if parent uses this XR kind
				usesThisXR := false
				for _, res := range parentComp.Resources {
					if res.BaseGVK.Kind == xrKind {
						usesThisXR = true
						break
					}
				}
				
				if !usesThisXR {
					continue
				}
				
				// Check if parent reads this specific status field
				parentReads := v.statusReads[parentComp.Name]
				for _, read := range parentReads {
					if read.ResourceGVK.Kind == xrKind && read.FromFieldPath == statusField {
						readByParent = true
						break
					}
				}
				
				if readByParent {
					break
				}
			}
			
			if readByParent {
				continue // Used by parent - not unused!
			}
			
			// Check 3: Is this XR even used by a parent?
			// If it's a root XR (not used by anyone), status fields are fine (used by external consumers)
			isUsedByAnyComposition := false
			for _, potentialParent := range v.compositions {
				for _, res := range potentialParent.Resources {
					if res.BaseGVK.Kind == xrKind {
						isUsedByAnyComposition = true
						break
					}
				}
				if isUsedByAnyComposition {
					break
				}
			}
			
			// Only warn if:
			// - This XR IS used by a parent (not a root XR)
			// - The status field is NOT read internally
			// - The status field is NOT read by any parent
			// - The status field is unused in ALL compositions for this XR kind
			if isUsedByAnyComposition {
				// Count how many compositions write this field
				usageCount := len(writingComps)
				totalComps := len(compositions)
				
				// Only warn if unused in ALL compositions
				// (Don't warn for provider-specific fields used in some but not all)
				if usageCount == totalComps {
					// All compositions write it but none read it - truly unused
					for _, compName := range writingComps {
						// Find the write info for error reporting
						writes := v.statusWrites[compName]
						for _, write := range writes {
							if write.ToFieldPath == statusField {
								issues = append(issues, StatusChainIssue{
									Severity:        "warning",
									CompositionName: compName,
									ResourceName:    write.ResourceName,
									StatusPath:      write.ToFieldPath,
									Message: fmt.Sprintf(
										"composition '%s' writes to '%s' but it's never read (not used internally or by parent)",
										compName, write.ToFieldPath),
									SourceFile: write.SourceFile,
									SourceLine: write.SourceLine,
								})
								break // Only report once per composition
							}
						}
					}
				}
			}
		}
	}
	
	return issues
}

// isProviderResource returns true if the GVK looks like a provider-managed resource
// (e.g., ec2.aws.upbound.io, managedidentity.azure.upbound.io) rather than a custom XR.
func isProviderResource(gvk schema.GroupVersionKind) bool {
	// Provider resources typically have groups like:
	// - *.aws.upbound.io
	// - *.azure.upbound.io
	// - *.gcp.upbound.io
	// - helm.crossplane.io
	// - kubernetes.crossplane.io
	
	group := gvk.Group
	
	// Check for common provider patterns
	providerPatterns := []string{
		".upbound.io",
		"helm.crossplane.io",
		"kubernetes.crossplane.io",
		".aws.crossplane.io",
		".azure.crossplane.io",
		".gcp.crossplane.io",
	}
	
	for _, pattern := range providerPatterns {
		if strings.Contains(group, pattern) {
			return true
		}
	}
	
	return false
}
