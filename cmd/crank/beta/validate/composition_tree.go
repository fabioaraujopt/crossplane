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
	"sort"
	"strings"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
)

// CompositionNode represents a node in the composition tree.
type CompositionNode struct {
	Name           string
	CompositeGVK   schema.GroupVersionKind
	Children       []*CompositionNode
	ChildResources []ChildResourceInfo
	Patches        []PatchInfo
	UsedParams     map[string]bool
	AllParams      []string
}

// ChildResourceInfo contains info about a child resource in a composition.
type ChildResourceInfo struct {
	Name        string
	GVK         schema.GroupVersionKind
	PatchCount  int
	IsXR        bool // True if this is another XR (not a managed resource)
	Composition *CompositionNode
}

// CompositionTree represents the full tree of compositions.
type CompositionTree struct {
	roots     []*CompositionNode
	nodesByGVK map[schema.GroupVersionKind]*CompositionNode
	allNodes  []*CompositionNode
}

// PerCompositionAnalysis contains analysis results for a single composition.
type PerCompositionAnalysis struct {
	CompositionName   string
	CompositeGVK      schema.GroupVersionKind
	TotalPatches      int
	ValidPatches      int
	InvalidPatches    int
	SkippedPatches    int
	InvalidPatchInfos []InvalidPathInfo
	TotalParams       int
	UsedParams        int
	UnusedParams      []string
	ChildResources    []ChildResourceInfo
}

// TreeAnalysisResult contains the full tree analysis.
type TreeAnalysisResult struct {
	PerComposition   map[string]*PerCompositionAnalysis
	Tree             *CompositionTree
	TotalCompositions int
	RootCompositions  []string
}

// BuildCompositionTree builds a tree from parsed compositions and CRDs.
func BuildCompositionTree(parser *CompositionParser, crds []*extv1.CustomResourceDefinition) *CompositionTree {
	tree := &CompositionTree{
		roots:      make([]*CompositionNode, 0),
		nodesByGVK: make(map[schema.GroupVersionKind]*CompositionNode),
		allNodes:   make([]*CompositionNode, 0),
	}

	// Build nodes for each composition
	for _, comp := range parser.GetCompositions() {
		node := &CompositionNode{
			Name:           comp.Name,
			CompositeGVK:   comp.CompositeTypeRef,
			Children:       make([]*CompositionNode, 0),
			ChildResources: make([]ChildResourceInfo, 0),
			Patches:        comp.AllPatches,
			UsedParams:     make(map[string]bool),
			AllParams:      make([]string, 0),
		}

		// Track child resources
		for _, res := range comp.Resources {
			if res.Base == nil {
				continue
			}

			childGVK := res.Base.GroupVersionKind()
			childInfo := ChildResourceInfo{
				Name:       res.Name,
				GVK:        childGVK,
				PatchCount: len(res.Patches),
				IsXR:       isXRGVK(childGVK, crds),
			}
			node.ChildResources = append(node.ChildResources, childInfo)
		}

		tree.allNodes = append(tree.allNodes, node)
		tree.nodesByGVK[comp.CompositeTypeRef] = node
	}

	// Link parent-child relationships
	for _, node := range tree.allNodes {
		for i, child := range node.ChildResources {
			if childNode, ok := tree.nodesByGVK[child.GVK]; ok {
				node.Children = append(node.Children, childNode)
				node.ChildResources[i].Composition = childNode
			}
		}
	}

	// Find root compositions (not referenced by any other composition)
	referenced := make(map[schema.GroupVersionKind]bool)
	for _, node := range tree.allNodes {
		for _, child := range node.Children {
			referenced[child.CompositeGVK] = true
		}
	}

	for _, node := range tree.allNodes {
		if !referenced[node.CompositeGVK] {
			tree.roots = append(tree.roots, node)
		}
	}

	return tree
}

// isXRGVK checks if a GVK is a Crossplane XR (has a corresponding XRD).
func isXRGVK(gvk schema.GroupVersionKind, crds []*extv1.CustomResourceDefinition) bool {
	for _, crd := range crds {
		if crd.Spec.Group == gvk.Group && crd.Spec.Names.Kind == gvk.Kind {
			return true
		}
	}
	return false
}

// AnalyzePerComposition performs analysis on each composition individually.
func AnalyzePerComposition(
	parser *CompositionParser,
	crds []*extv1.CustomResourceDefinition,
	navigator *SchemaNavigator,
) (*TreeAnalysisResult, error) {
	result := &TreeAnalysisResult{
		PerComposition: make(map[string]*PerCompositionAnalysis),
	}

	tree := BuildCompositionTree(parser, crds)
	result.Tree = tree
	result.TotalCompositions = len(tree.allNodes)

	for _, root := range tree.roots {
		result.RootCompositions = append(result.RootCompositions, root.Name)
	}

	// Analyze each composition
	for _, comp := range parser.GetCompositions() {
		analysis := &PerCompositionAnalysis{
			CompositionName:   comp.Name,
			CompositeGVK:      comp.CompositeTypeRef,
			InvalidPatchInfos: make([]InvalidPathInfo, 0),
			UnusedParams:      make([]string, 0),
			ChildResources:    make([]ChildResourceInfo, 0),
		}

		// Track used parameters for this composition
		usedParams := make(map[string]bool)

		// Validate patches
		for _, patchInfo := range comp.AllPatches {
			analysis.TotalPatches++

			hasError := false
			hasSchema := true

			// Validate fromFieldPath
			if patchInfo.Patch.FromFieldPath != "" {
				if navigator.HasSchema(patchInfo.SourceGVK) {
					validation := navigator.ValidatePath(patchInfo.SourceGVK, patchInfo.Patch.FromFieldPath)
					if !validation.Valid {
						hasError = true
						analysis.InvalidPatchInfos = append(analysis.InvalidPatchInfos, InvalidPathInfo{
							CompositionName: patchInfo.CompositionName,
							ResourceName:    patchInfo.ResourceName,
							PatchIndex:      patchInfo.PatchIndex,
							Path:            patchInfo.Patch.FromFieldPath,
							PathType:        "fromFieldPath",
							Reason:          fmt.Sprintf("%s (at '%s')", validation.Reason, validation.InvalidSegment),
							SourceGVK:       patchInfo.SourceGVK,
							TargetGVK:       patchInfo.TargetGVK,
						})
					} else {
						// Track as used
						usedParams[patchInfo.Patch.FromFieldPath] = true
						markParentsUsed(patchInfo.Patch.FromFieldPath, usedParams)
					}
				} else {
					hasSchema = false
				}
			}

			// Validate toFieldPath
			if patchInfo.Patch.ToFieldPath != "" {
				if navigator.HasSchema(patchInfo.TargetGVK) {
					validation := navigator.ValidatePath(patchInfo.TargetGVK, patchInfo.Patch.ToFieldPath)
					if !validation.Valid {
						hasError = true
						analysis.InvalidPatchInfos = append(analysis.InvalidPatchInfos, InvalidPathInfo{
							CompositionName: patchInfo.CompositionName,
							ResourceName:    patchInfo.ResourceName,
							PatchIndex:      patchInfo.PatchIndex,
							Path:            patchInfo.Patch.ToFieldPath,
							PathType:        "toFieldPath",
							Reason:          fmt.Sprintf("%s (at '%s')", validation.Reason, validation.InvalidSegment),
							SourceGVK:       patchInfo.SourceGVK,
							TargetGVK:       patchInfo.TargetGVK,
						})
					}
				} else {
					hasSchema = false
				}
			}

			// Validate combine variables
			if patchInfo.Patch.Combine != nil {
				for _, v := range patchInfo.Patch.Combine.Variables {
					if v.FromFieldPath != "" {
						if navigator.HasSchema(patchInfo.SourceGVK) {
							validation := navigator.ValidatePath(patchInfo.SourceGVK, v.FromFieldPath)
							if !validation.Valid {
								hasError = true
							} else {
								usedParams[v.FromFieldPath] = true
								markParentsUsed(v.FromFieldPath, usedParams)
							}
						}
					}
				}
			}

			if hasError {
				analysis.InvalidPatches++
			} else if !hasSchema {
				analysis.SkippedPatches++
			} else {
				analysis.ValidPatches++
			}
		}

		// Get all params for this XRD and find unused
		xrdSchema := navigator.GetSchemaForGVK(comp.CompositeTypeRef)
		if xrdSchema != nil {
			// Get spec.parameters paths
			allParams := ExtractParameterPaths(xrdSchema, "", 10)
			analysis.TotalParams = len(allParams)

			// Filter to just spec.parameters.* paths
			for _, param := range allParams {
				if strings.HasPrefix(param, "spec.parameters.") {
					if !usedParams[param] && !hasUsedChild(param, usedParams) {
						analysis.UnusedParams = append(analysis.UnusedParams, param)
					} else {
						analysis.UsedParams++
					}
				}
			}
		}

		// Get child resources
		if node, ok := tree.nodesByGVK[comp.CompositeTypeRef]; ok {
			analysis.ChildResources = node.ChildResources
		}

		result.PerComposition[comp.Name] = analysis
	}

	return result, nil
}

func markParentsUsed(path string, usedParams map[string]bool) {
	parts := strings.Split(path, ".")
	for i := 1; i < len(parts); i++ {
		parentPath := strings.Join(parts[:i], ".")
		usedParams[parentPath] = true
	}
}

func hasUsedChild(path string, usedParams map[string]bool) bool {
	prefix := path + "."
	for p := range usedParams {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// PrintTreeAnalysis prints a detailed tree analysis.
func PrintTreeAnalysis(result *TreeAnalysisResult, w io.Writer, showDetails bool) error {
	if _, err := fmt.Fprintf(w, "\n=== Composition Tree Analysis ===\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if _, err := fmt.Fprintf(w, "Total compositions: %d\n", result.TotalCompositions); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	if _, err := fmt.Fprintf(w, "Root compositions: %s\n", strings.Join(result.RootCompositions, ", ")); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	// Print tree structure
	if _, err := fmt.Fprintf(w, "\n--- Composition Hierarchy ---\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	for _, root := range result.Tree.roots {
		if err := printNode(root, w, "", true); err != nil {
			return err
		}
	}

	// Print per-composition analysis
	if _, err := fmt.Fprintf(w, "\n--- Per-Composition Analysis ---\n"); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	// Sort by name for consistent output
	names := make([]string, 0, len(result.PerComposition))
	for name := range result.PerComposition {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		analysis := result.PerComposition[name]

		if _, err := fmt.Fprintf(w, "\n[%s] (%s)\n", analysis.CompositionName, analysis.CompositeGVK.Kind); err != nil {
			return errors.Wrap(err, "cannot write output")
		}

		if _, err := fmt.Fprintf(w, "  Patches: %d total, %d valid, %d invalid, %d skipped\n",
			analysis.TotalPatches, analysis.ValidPatches, analysis.InvalidPatches, analysis.SkippedPatches); err != nil {
			return errors.Wrap(err, "cannot write output")
		}

		// Show invalid patches
		if len(analysis.InvalidPatchInfos) > 0 && showDetails {
			if _, err := fmt.Fprintf(w, "  Invalid patches:\n"); err != nil {
				return errors.Wrap(err, "cannot write output")
			}
			for _, inv := range analysis.InvalidPatchInfos {
				if _, err := fmt.Fprintf(w, "    [x] %s/%s patch[%d] %s: '%s' - %s\n",
					inv.CompositionName, inv.ResourceName, inv.PatchIndex, inv.PathType, inv.Path, inv.Reason); err != nil {
					return errors.Wrap(err, "cannot write output")
				}
			}
		}

		// Show unused params
		if len(analysis.UnusedParams) > 0 {
			if _, err := fmt.Fprintf(w, "  Unused parameters: %d\n", len(analysis.UnusedParams)); err != nil {
				return errors.Wrap(err, "cannot write output")
			}
			if showDetails {
				for _, param := range analysis.UnusedParams {
					if _, err := fmt.Fprintf(w, "    - %s\n", param); err != nil {
						return errors.Wrap(err, "cannot write output")
					}
				}
			}
		} else {
			if _, err := fmt.Fprintf(w, "  Unused parameters: 0 ✓\n"); err != nil {
				return errors.Wrap(err, "cannot write output")
			}
		}

		// Show child XRs
		xrChildren := 0
		for _, child := range analysis.ChildResources {
			if child.IsXR {
				xrChildren++
			}
		}
		if xrChildren > 0 {
			if _, err := fmt.Fprintf(w, "  Child compositions: %d\n", xrChildren); err != nil {
				return errors.Wrap(err, "cannot write output")
			}
			if showDetails {
				for _, child := range analysis.ChildResources {
					if child.IsXR {
						if _, err := fmt.Fprintf(w, "    → %s (%s)\n", child.Name, child.GVK.Kind); err != nil {
							return errors.Wrap(err, "cannot write output")
						}
					}
				}
			}
		}
	}

	return nil
}

func printNode(node *CompositionNode, w io.Writer, prefix string, isLast bool) error {
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	if _, err := fmt.Fprintf(w, "%s%s%s (%s)\n", prefix, connector, node.Name, node.CompositeGVK.Kind); err != nil {
		return errors.Wrap(err, "cannot write output")
	}

	childPrefix := prefix
	if isLast {
		childPrefix += "    "
	} else {
		childPrefix += "│   "
	}

	for i, child := range node.Children {
		isChildLast := i == len(node.Children)-1
		if err := printNode(child, w, childPrefix, isChildLast); err != nil {
			return err
		}
	}

	return nil
}
