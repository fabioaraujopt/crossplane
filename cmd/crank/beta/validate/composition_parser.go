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
	"encoding/json"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"
	"github.com/crossplane/crossplane-runtime/v2/pkg/fieldpath"

	"github.com/crossplane/crossplane/v2/cmd/crank/common/load"
)

// PatchType defines the type of patch operation.
type PatchType string

const (
	// PatchTypeFromCompositeFieldPath patches from composite resource to composed resource.
	PatchTypeFromCompositeFieldPath PatchType = "FromCompositeFieldPath"
	// PatchTypeToCompositeFieldPath patches from composed resource to composite resource.
	PatchTypeToCompositeFieldPath PatchType = "ToCompositeFieldPath"
	// PatchTypeCombineFromComposite combines multiple fields from composite.
	PatchTypeCombineFromComposite PatchType = "CombineFromComposite"
	// PatchTypeCombineToComposite combines multiple fields to composite.
	PatchTypeCombineToComposite PatchType = "CombineToComposite"
	// PatchTypeFromEnvironmentFieldPath patches from environment config.
	PatchTypeFromEnvironmentFieldPath PatchType = "FromEnvironmentFieldPath"
	// PatchTypeToEnvironmentFieldPath patches to environment config.
	PatchTypeToEnvironmentFieldPath PatchType = "ToEnvironmentFieldPath"
	// PatchTypePatchSet references a reusable PatchSet.
	PatchTypePatchSet PatchType = "PatchSet"
)

// CombineVariable represents a variable in a Combine patch.
type CombineVariable struct {
	FromFieldPath string `json:"fromFieldPath"`
}

// CombineString represents the string configuration in a Combine patch.
type CombineString struct {
	Format string `json:"fmt,omitempty"`
	Type   string `json:"type,omitempty"`
}

// Combine represents combine configuration in a patch.
type Combine struct {
	Variables []CombineVariable `json:"variables,omitempty"`
	Strategy  string            `json:"strategy,omitempty"`
	String    *CombineString    `json:"string,omitempty"`
}

// PatchPolicy represents the policy configuration for a patch.
type PatchPolicy struct {
	FromFieldPath string `json:"fromFieldPath,omitempty"` // "Required" or "Optional"
}

// Patch represents a patch in a composition.
type Patch struct {
	Type          PatchType    `json:"type,omitempty"`
	FromFieldPath string       `json:"fromFieldPath,omitempty"`
	ToFieldPath   string       `json:"toFieldPath,omitempty"`
	Combine       *Combine     `json:"combine,omitempty"`
	PatchSetName  string       `json:"patchSetName,omitempty"` // For PatchSet references
	Transforms    []Transform  `json:"transforms,omitempty"`
	Policy        *PatchPolicy `json:"policy,omitempty"` // Policy for handling missing fields
}

// Transform represents a transformation applied to a patch value.
type Transform struct {
	Type    string            `json:"type,omitempty"`
	Convert *ConvertTransform `json:"convert,omitempty"`
	String  *StringTransform  `json:"string,omitempty"`
	Math    *MathTransform    `json:"math,omitempty"`
	Map     map[string]string `json:"map,omitempty"`
}

// ConvertTransform converts a value to a different type.
type ConvertTransform struct {
	ToType string `json:"toType,omitempty"`
}

// StringTransform applies string operations.
type StringTransform struct {
	Type    string `json:"type,omitempty"`
	Format  string `json:"fmt,omitempty"`
	Convert string `json:"convert,omitempty"` // For type: Convert - e.g., ToUpper, ToLower, ToBase64, etc.
}

// MathTransform applies math operations.
type MathTransform struct {
	Type     string `json:"type,omitempty"`
	Multiply *int64 `json:"multiply,omitempty"`
}

// PatchSet represents a reusable set of patches.
type PatchSet struct {
	Name    string  `json:"name"`
	Patches []Patch `json:"patches,omitempty"`
}

// ComposedResource represents a resource in a composition.
type ComposedResource struct {
	Name                 string                     `json:"name"`
	Base                 *unstructured.Unstructured `json:"base,omitempty"`
	BaseGVK              schema.GroupVersionKind    // GVK of the base resource
	Patches              []Patch                    `json:"patches,omitempty"`
	CompositionSelector  map[string]string          // compositionSelector.matchLabels for child XRs
}

// PatchAndTransformInput represents the input to function-patch-and-transform.
type PatchAndTransformInput struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Resources  []ComposedResource `json:"resources,omitempty"`
	PatchSets  []PatchSet         `json:"patchSets,omitempty"`
}

// ParsedComposition represents a parsed composition with extracted information.
type ParsedComposition struct {
	Name             string
	CompositeTypeRef schema.GroupVersionKind
	Labels           map[string]string // metadata.labels for composition selection
	Resources        []ComposedResource
	AllPatches       []PatchInfo
	SourceFile       string // Source file path
	SourceLine       int    // Source line number
}

// PatchInfo contains detailed information about a patch for validation.
type PatchInfo struct {
	CompositionName string
	ResourceName    string
	PatchIndex      int
	Patch           Patch
	SourceGVK       schema.GroupVersionKind // The GVK of the source (XR or composed resource)
	TargetGVK       schema.GroupVersionKind // The GVK of the target (XR or composed resource)
	SourceFile      string                  // Source file path
	SourceLine      int                     // Source line number (of the composition)
}

// CompositionParser parses compositions and extracts patch information.
type CompositionParser struct {
	compositions []*ParsedComposition
}

// NewCompositionParser creates a new CompositionParser.
func NewCompositionParser() *CompositionParser {
	return &CompositionParser{
		compositions: make([]*ParsedComposition, 0),
	}
}

// Parse parses unstructured compositions and extracts patch information.
func (p *CompositionParser) Parse(objects []*unstructured.Unstructured) error {
	for _, obj := range objects {
		gvk := obj.GroupVersionKind()

		// Only process Composition objects
		if gvk.Group != "apiextensions.crossplane.io" || gvk.Kind != "Composition" {
			continue
		}

		parsed, err := p.parseComposition(obj)
		if err != nil {
			return errors.Wrapf(err, "cannot parse composition %q", obj.GetName())
		}

		p.compositions = append(p.compositions, parsed)
	}

	return nil
}

// GetCompositions returns all parsed compositions.
func (p *CompositionParser) GetCompositions() []*ParsedComposition {
	return p.compositions
}

// parseComposition parses a single composition.
func (p *CompositionParser) parseComposition(obj *unstructured.Unstructured) (*ParsedComposition, error) {
	paved := fieldpath.Pave(obj.Object)

	// Extract compositeTypeRef
	apiVersion, err := paved.GetString("spec.compositeTypeRef.apiVersion")
	if err != nil {
		return nil, errors.Wrap(err, "cannot get compositeTypeRef.apiVersion")
	}

	kind, err := paved.GetString("spec.compositeTypeRef.kind")
	if err != nil {
		return nil, errors.Wrap(err, "cannot get compositeTypeRef.kind")
	}

	gv := strings.Split(apiVersion, "/")
	var group, version string
	if len(gv) == 2 {
		group = gv[0]
		version = gv[1]
	} else {
		version = apiVersion
	}

	compositeGVK := schema.GroupVersionKind{
		Group:   group,
		Version: version,
		Kind:    kind,
	}

	// Get source file and line from annotations
	sourceFile := load.GetSourceFile(obj)
	sourceLine := load.GetSourceLine(obj)

	// Extract labels from metadata
	labels := make(map[string]string)
	if obj.GetLabels() != nil {
		labels = obj.GetLabels()
	}

	parsed := &ParsedComposition{
		Name:             obj.GetName(),
		CompositeTypeRef: compositeGVK,
		Labels:           labels,
		Resources:        make([]ComposedResource, 0),
		AllPatches:       make([]PatchInfo, 0),
		SourceFile:       sourceFile,
		SourceLine:       sourceLine,
	}

	// Extract pipeline steps and look for patch-and-transform inputs
	pipeline, err := paved.GetValue("spec.pipeline")
	if err != nil {
		// No pipeline, might be legacy composition
		return parsed, nil
	}

	pipelineSlice, ok := pipeline.([]interface{})
	if !ok {
		return parsed, nil
	}

	for _, step := range pipelineSlice {
		stepMap, ok := step.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is a patch-and-transform step
		input, ok := stepMap["input"].(map[string]interface{})
		if !ok {
			continue
		}

		inputKind, _ := input["kind"].(string)
		if inputKind != "Resources" {
			continue
		}

		// Parse patchSets first (for resolution)
		patchSetsMap := make(map[string][]Patch)
		if patchSets, ok := input["patchSets"].([]interface{}); ok {
			for _, ps := range patchSets {
				psMap, ok := ps.(map[string]interface{})
				if !ok {
					continue
				}
				psName := getStringField(psMap, "name")
				if psName == "" {
					continue
				}
				psPatches, ok := psMap["patches"].([]interface{})
				if !ok {
					continue
				}
				for _, psPatch := range psPatches {
					psPatchMap, ok := psPatch.(map[string]interface{})
					if !ok {
						continue
					}
					patchSetsMap[psName] = append(patchSetsMap[psName], p.parsePatch(psPatchMap))
				}
			}
		}

		// Parse resources
		resources, ok := input["resources"].([]interface{})
		if !ok {
			continue
		}

		for _, res := range resources {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			composedRes := ComposedResource{
				Name:    getStringField(resMap, "name"),
				Patches: make([]Patch, 0),
			}

			// Parse base
			if base, ok := resMap["base"].(map[string]interface{}); ok {
				composedRes.Base = &unstructured.Unstructured{Object: base}
				// Extract GVK from base
				composedRes.BaseGVK = composedRes.Base.GroupVersionKind()

				// Extract compositionSelector.matchLabels (for child XRs)
				// Check both spec.compositionSelector and spec.crossplane.compositionSelector
				if spec, ok := base["spec"].(map[string]interface{}); ok {
					// Try spec.compositionSelector first
					if selector, ok := spec["compositionSelector"].(map[string]interface{}); ok {
						if matchLabels, ok := selector["matchLabels"].(map[string]interface{}); ok {
							composedRes.CompositionSelector = make(map[string]string)
							for k, v := range matchLabels {
								if strVal, ok := v.(string); ok {
									composedRes.CompositionSelector[k] = strVal
								}
							}
						}
					}
					// Also try spec.crossplane.compositionSelector (Crossplane v2 style)
					if composedRes.CompositionSelector == nil {
						if crossplane, ok := spec["crossplane"].(map[string]interface{}); ok {
							if selector, ok := crossplane["compositionSelector"].(map[string]interface{}); ok {
								if matchLabels, ok := selector["matchLabels"].(map[string]interface{}); ok {
									composedRes.CompositionSelector = make(map[string]string)
									for k, v := range matchLabels {
										if strVal, ok := v.(string); ok {
											composedRes.CompositionSelector[k] = strVal
										}
									}
								}
							}
						}
					}
				}
			}

			// Parse patches (optional - resource may have no patches)
			patches, _ := resMap["patches"].([]interface{})

			patchIndex := 0
			for _, patch := range patches {
				patchMap, ok := patch.(map[string]interface{})
				if !ok {
					continue
				}

				parsedPatch := p.parsePatch(patchMap)

				// Check if this is a PatchSet reference
				if parsedPatch.PatchSetName != "" {
					// Resolve PatchSet to its patches
					psPatches, found := patchSetsMap[parsedPatch.PatchSetName]
					if found {
						for _, psPatch := range psPatches {
							composedRes.Patches = append(composedRes.Patches, psPatch)

							// Create PatchInfo for each patch in the set
							var sourceGVK, targetGVK schema.GroupVersionKind
							switch psPatch.Type {
							case PatchTypeFromCompositeFieldPath, PatchTypeCombineFromComposite:
								sourceGVK = compositeGVK
								if composedRes.Base != nil {
									targetGVK = composedRes.Base.GroupVersionKind()
								}
							case PatchTypeToCompositeFieldPath, PatchTypeCombineToComposite:
								if composedRes.Base != nil {
									sourceGVK = composedRes.Base.GroupVersionKind()
								}
								targetGVK = compositeGVK
							default:
								sourceGVK = compositeGVK
								if composedRes.Base != nil {
									targetGVK = composedRes.Base.GroupVersionKind()
								}
							}

							patchInfo := PatchInfo{
								CompositionName: obj.GetName(),
								ResourceName:    composedRes.Name,
								PatchIndex:      patchIndex,
								Patch:           psPatch,
								SourceGVK:       sourceGVK,
								TargetGVK:       targetGVK,
								SourceFile:      sourceFile,
								SourceLine:      sourceLine,
							}
							parsed.AllPatches = append(parsed.AllPatches, patchInfo)
							patchIndex++
						}
					}
					continue
				}

				composedRes.Patches = append(composedRes.Patches, parsedPatch)

				// Determine source and target GVKs based on patch type
				var sourceGVK, targetGVK schema.GroupVersionKind

				switch parsedPatch.Type {
				case PatchTypeFromCompositeFieldPath, PatchTypeCombineFromComposite:
					sourceGVK = compositeGVK
					if composedRes.Base != nil {
						targetGVK = composedRes.Base.GroupVersionKind()
					}
				case PatchTypeToCompositeFieldPath, PatchTypeCombineToComposite:
					if composedRes.Base != nil {
						sourceGVK = composedRes.Base.GroupVersionKind()
					}
					targetGVK = compositeGVK
				default:
					// Default to FromCompositeFieldPath if not specified
					sourceGVK = compositeGVK
					if composedRes.Base != nil {
						targetGVK = composedRes.Base.GroupVersionKind()
					}
				}

				// Try to find exact line number for this patch
				patchLine := sourceLine
				if sourceFile != "" {
					if exactLine := load.FindPatchLineInComposition(sourceFile, composedRes.Name, patchIndex); exactLine > 0 {
						patchLine = exactLine
					}
				}

				patchInfo := PatchInfo{
					CompositionName: obj.GetName(),
					ResourceName:    composedRes.Name,
					PatchIndex:      patchIndex,
					Patch:           parsedPatch,
					SourceGVK:       sourceGVK,
					TargetGVK:       targetGVK,
					SourceFile:      sourceFile,
					SourceLine:      patchLine,
				}

				parsed.AllPatches = append(parsed.AllPatches, patchInfo)
				patchIndex++
			}

			parsed.Resources = append(parsed.Resources, composedRes)
		}
	}

	return parsed, nil
}

// parsePatch parses a patch map into a Patch struct.
func (p *CompositionParser) parsePatch(patchMap map[string]interface{}) Patch {
	patch := Patch{
		Type:          PatchType(getStringField(patchMap, "type")),
		FromFieldPath: getStringField(patchMap, "fromFieldPath"),
		ToFieldPath:   getStringField(patchMap, "toFieldPath"),
		PatchSetName:  getStringField(patchMap, "patchSetName"),
	}

	// Default type (unless it's a PatchSet reference)
	if patch.Type == "" && patch.PatchSetName == "" {
		patch.Type = PatchTypeFromCompositeFieldPath
	}

	// Parse combine if present
	if combine, ok := patchMap["combine"].(map[string]interface{}); ok {
		patch.Combine = &Combine{
			Strategy: getStringField(combine, "strategy"),
		}

		if variables, ok := combine["variables"].([]interface{}); ok {
			for _, v := range variables {
				if varMap, ok := v.(map[string]interface{}); ok {
					patch.Combine.Variables = append(patch.Combine.Variables, CombineVariable{
						FromFieldPath: getStringField(varMap, "fromFieldPath"),
					})
				}
			}
		}

		// Parse string configuration if present
		if strConfig, ok := combine["string"].(map[string]interface{}); ok {
			patch.Combine.String = &CombineString{
				Format: getStringField(strConfig, "fmt"),
				Type:   getStringField(strConfig, "type"),
			}
		}
	}

	// Parse transforms if present
	if transforms, ok := patchMap["transforms"].([]interface{}); ok {
		for _, t := range transforms {
			if tMap, ok := t.(map[string]interface{}); ok {
				transform := Transform{
					Type: getStringField(tMap, "type"),
				}

				// Parse convert transform
				if convert, ok := tMap["convert"].(map[string]interface{}); ok {
					transform.Convert = &ConvertTransform{
						ToType: getStringField(convert, "toType"),
					}
				}

				// Parse string transform
				if str, ok := tMap["string"].(map[string]interface{}); ok {
					transform.String = &StringTransform{
						Type:    getStringField(str, "type"),
						Format:  getStringField(str, "fmt"),
						Convert: getStringField(str, "convert"),
					}
				}

				// Parse map transform
				if mapTransform, ok := tMap["map"].(map[string]interface{}); ok {
					transform.Map = make(map[string]string)
					for k, v := range mapTransform {
						if strV, ok := v.(string); ok {
							transform.Map[k] = strV
						}
					}
				}

				patch.Transforms = append(patch.Transforms, transform)
			}
		}
	}

	// Parse policy if present
	if policy, ok := patchMap["policy"].(map[string]interface{}); ok {
		patch.Policy = &PatchPolicy{
			FromFieldPath: getStringField(policy, "fromFieldPath"),
		}
	}

	return patch
}

// GetAllFromFieldPaths returns all fromFieldPath values from all patches.
func (p *CompositionParser) GetAllFromFieldPaths() []string {
	paths := make([]string, 0)
	seen := make(map[string]bool)

	for _, comp := range p.compositions {
		for _, patchInfo := range comp.AllPatches {
			// Add fromFieldPath
			if patchInfo.Patch.FromFieldPath != "" && !seen[patchInfo.Patch.FromFieldPath] {
				paths = append(paths, patchInfo.Patch.FromFieldPath)
				seen[patchInfo.Patch.FromFieldPath] = true
			}

			// Add combine variables
			if patchInfo.Patch.Combine != nil {
				for _, v := range patchInfo.Patch.Combine.Variables {
					if v.FromFieldPath != "" && !seen[v.FromFieldPath] {
						paths = append(paths, v.FromFieldPath)
						seen[v.FromFieldPath] = true
					}
				}
			}
		}
	}

	return paths
}

// GetFromFieldPathsForXR returns fromFieldPaths that read from the composite resource.
func (p *CompositionParser) GetFromFieldPathsForXR(xrGVK schema.GroupVersionKind) []string {
	paths := make([]string, 0)
	seen := make(map[string]bool)

	for _, comp := range p.compositions {
		if comp.CompositeTypeRef != xrGVK {
			continue
		}

		for _, patchInfo := range comp.AllPatches {
			switch patchInfo.Patch.Type {
			case PatchTypeFromCompositeFieldPath, PatchTypeCombineFromComposite, "":
				// These read from the XR
				if patchInfo.Patch.FromFieldPath != "" && !seen[patchInfo.Patch.FromFieldPath] {
					paths = append(paths, patchInfo.Patch.FromFieldPath)
					seen[patchInfo.Patch.FromFieldPath] = true
				}

				if patchInfo.Patch.Combine != nil {
					for _, v := range patchInfo.Patch.Combine.Variables {
						if v.FromFieldPath != "" && !seen[v.FromFieldPath] {
							paths = append(paths, v.FromFieldPath)
							seen[v.FromFieldPath] = true
						}
					}
				}
			}
		}
	}

	return paths
}

// ToJSON converts the parsed compositions to JSON for debugging.
func (p *CompositionParser) ToJSON() ([]byte, error) {
	return json.MarshalIndent(p.compositions, "", "  ")
}

func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
