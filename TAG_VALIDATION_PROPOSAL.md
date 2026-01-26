# Tag Validation Enhancement Proposal

## Problem Statement

Cloud resources (AWS/Azure) created via Crossplane compositions often end up untagged or partially tagged because:

1. **Compositions missing `function-tag-manager`** in their pipeline
2. **Parent compositions not propagating `spec.parameters.tags`** to child compositions
3. **Tag-manager missing required tags** (StampName, Environment, ManagedBy)
4. **No validation** that tags will actually reach cloud resources

This results in:
- Untagged AWS/Azure resources
- Cost allocation issues
- Security/compliance violations
- Difficult resource ownership tracking

## Proposed Solution

Add a new `TagValidator` to the Crossplane validator that performs static analysis of compositions to detect tagging issues **before** resources are created.

---

## Detection Rules

### Rule 1: Composition Creating Cloud Resources Without Tag-Manager

**Detection:** A composition that creates AWS/Azure managed resources but doesn't include `function-tag-manager` in its pipeline.

```yaml
# ❌ BAD: Creates AWS resources without tag-manager
apiVersion: apiextensions.crossplane.io/v2
kind: Composition
spec:
  compositeTypeRef:
    apiVersion: cloud.example.com/v1alpha1
    kind: MyComposition
  mode: Pipeline
  pipeline:
    - step: render
      functionRef:
        name: crossplane-function-patch-and-transform
      input:
        resources:
          - name: s3-bucket
            base:
              apiVersion: s3.aws.upbound.io/v1beta1  # ← AWS resource
              kind: Bucket
    # ❌ Missing function-tag-manager step!
```

**Warning:**
```
[!] composition.yaml: Composition creates AWS/Azure resources but has no function-tag-manager
    Resources affected: s3.aws.upbound.io/v1beta1/Bucket
    Action: Add function-tag-manager to pipeline
```

---

### Rule 2: Tag-Manager Without Required Tags

**Detection:** A composition has `function-tag-manager` but is missing required tags.

**Configuration (configurable list of required tags):**
```yaml
# Default required tags
requiredTags:
  - ManagedBy
  - StampName      # or TenantName
  - Environment
  - StampVersion   # optional
```

**Warning:**
```
[!] composition.yaml: function-tag-manager missing required tags
    Missing: StampName, Environment
    Has: ManagedBy, StampVersion
    Action: Add missing tags via FromValue or FromCompositeFieldPath
```

---

### Rule 3: Tags Not Propagated to Child Composition

**Detection:** A child composition uses `fromFieldPath: spec.parameters.tags` in its tag-manager, but the parent composition doesn't patch `spec.parameters.tags` to it.

```yaml
# Parent composition - ❌ BAD
- name: my-child
  base:
    kind: ChildCompositionV2
    spec:
      parameters:
        region: ""
        # Missing tags: ""
  patches:
    - fromFieldPath: spec.parameters.region
      toFieldPath: spec.parameters.region
    # ❌ Missing: spec.parameters.tags patch!
```

**Warning:**
```
[!] parent-composition.yaml: Child 'ChildCompositionV2' expects tags but parent doesn't propagate them
    Child uses: fromFieldPath: spec.parameters.tags in tag-manager
    Parent patches: region, clusterName, ... (no tags)
    Action: Add patch for spec.parameters.tags
```

---

### Rule 4: Cloud Resource Without Tag Path

**Detection:** An AWS/Azure resource is created but there's no path from `function-tag-manager` → resource.

This can happen when:
- Tag-manager uses `FromCompositeFieldPath` but field is never populated
- Resource is in a sub-composition that doesn't receive tags

**Warning:**
```
[!] composition.yaml: Resource 'my-rds-cluster' (rds.aws.upbound.io/v1beta1/Cluster) may not receive tags
    Reason: spec.parameters.tags is never populated (parent doesn't pass it)
    Tag-manager config: FromCompositeFieldPath: spec.parameters.tags
    Action: Ensure parent composition passes tags
```

---

## Implementation

### New File: `tag_validator.go`

```go
package validate

import (
    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TagValidationConfig configures tag validation behavior
type TagValidationConfig struct {
    RequiredTags     []string // Tags that must be present (default: ManagedBy, StampName, Environment)
    CloudProviders   []string // Provider prefixes to detect (default: aws.upbound.io, azure.upbound.io)
    TagManagerFunc   string   // Name of tag-manager function (default: crossplane-function-tag-manager)
    SkipCompositions []string // Composition names to skip
}

// TagValidator validates tagging patterns in compositions
type TagValidator struct {
    config TagValidationConfig
}

// TagValidationResult contains validation results
type TagValidationResult struct {
    Warnings []TagWarning
    Errors   []TagError
}

type TagWarning struct {
    File        string
    Line        int
    Composition string
    Rule        string   // e.g., "missing-tag-manager", "missing-required-tags", "tags-not-propagated"
    Message     string
    Affected    []string // Affected resources
    Action      string   // Recommended action
}

// Validate performs tag validation on compositions
func (v *TagValidator) Validate(compositions []*CompositionInfo) TagValidationResult {
    var result TagValidationResult
    
    for _, comp := range compositions {
        // Rule 1: Check for tag-manager in pipeline
        if v.createsCloudResources(comp) && !v.hasTagManager(comp) {
            result.Warnings = append(result.Warnings, TagWarning{
                File:        comp.SourceFile,
                Composition: comp.Name,
                Rule:        "missing-tag-manager",
                Message:     "Composition creates cloud resources without function-tag-manager",
                Affected:    v.getCloudResources(comp),
                Action:      "Add function-tag-manager to pipeline",
            })
        }
        
        // Rule 2: Check required tags in tag-manager
        if v.hasTagManager(comp) {
            missing := v.getMissingRequiredTags(comp)
            if len(missing) > 0 {
                result.Warnings = append(result.Warnings, TagWarning{
                    File:        comp.SourceFile,
                    Composition: comp.Name,
                    Rule:        "missing-required-tags",
                    Message:     fmt.Sprintf("Tag-manager missing required tags: %v", missing),
                    Action:      "Add missing tags via FromValue or FromCompositeFieldPath",
                })
            }
        }
        
        // Rule 3: Check tag propagation to child compositions
        for _, child := range v.getChildCompositions(comp) {
            if v.childExpectsTags(child) && !v.parentPassesTags(comp, child) {
                result.Warnings = append(result.Warnings, TagWarning{
                    File:        comp.SourceFile,
                    Composition: comp.Name,
                    Rule:        "tags-not-propagated",
                    Message:     fmt.Sprintf("Child '%s' expects tags but parent doesn't propagate them", child.Kind),
                    Action:      "Add patch: spec.parameters.tags → spec.parameters.tags",
                })
            }
        }
    }
    
    return result
}

// Helper methods

func (v *TagValidator) createsCloudResources(comp *CompositionInfo) bool {
    for _, res := range comp.Resources {
        apiVersion := res.Object.GetAPIVersion()
        for _, provider := range v.config.CloudProviders {
            if strings.Contains(apiVersion, provider) {
                return true
            }
        }
    }
    return false
}

func (v *TagValidator) hasTagManager(comp *CompositionInfo) bool {
    for _, step := range comp.Pipeline {
        if step.FunctionRef.Name == v.config.TagManagerFunc {
            return true
        }
    }
    return false
}

func (v *TagValidator) childExpectsTags(child ChildComposition) bool {
    // Check if child's tag-manager uses FromCompositeFieldPath: spec.parameters.tags
    // This requires fetching and parsing the child composition
    // ...
}

func (v *TagValidator) parentPassesTags(parent *CompositionInfo, child ChildComposition) bool {
    // Check if parent has a patch:
    // fromFieldPath: spec.parameters.tags
    // toFieldPath: spec.parameters.tags
    for _, patch := range child.Patches {
        if patch.FromFieldPath == "spec.parameters.tags" && 
           patch.ToFieldPath == "spec.parameters.tags" {
            return true
        }
    }
    return false
}
```

---

## CLI Integration

### New Flags

```go
// In cmd.go
ValidateTags      bool     `default:"true"  help:"Validate cloud resource tagging patterns."`
RequiredTags      []string `default:"ManagedBy,StampName,Environment" help:"Required tags for cloud resources."`
ShowTagAnalysis   bool     `default:"false" help:"Show detailed tag propagation analysis."`
```

### Output Example

```
$ crossplane beta validate . --validate-tags --show-tag-analysis

🏷️  Tag Validation Results
══════════════════════════════════════════════════════════════

[!] Stamp/StampTemporalV2/composition-aws.yaml
    Rule: tags-not-propagated
    Child 'StampTemporalV2' expects tags but parent doesn't pass them
    → Action: Add patch for spec.parameters.tags

[!] Stamp/StampAccessLogsV2/composition-aws.yaml  
    Rule: missing-required-tags
    Tag-manager missing: StampName, Environment
    → Action: Ensure spec.parameters.tags is propagated from parent

✓ Stamp/StampNetworkingV2/composition-aws.yaml - Tags properly configured
✓ Stamp/StampClusterV2/composition-aws.yaml - Tags properly configured

══════════════════════════════════════════════════════════════
Tag Analysis Summary:
  Compositions with cloud resources: 25
  Properly tagged: 23
  Missing tag-manager: 0
  Missing tag propagation: 2
  
Tag Propagation Tree:
  PlatformStampV2
    ├─→ StampCommonV2 ✓
    │   ├─→ StampNetworkingV2 ✓
    │   ├─→ StampClusterV2 ✓
    │   ├─→ StampTemporalV2 ❌ (tags not passed)
    │   └─→ ...
    └─→ StampAccessLogsV2 ❌ (tags not passed)
```

---

## Detection of Cloud Resource Types

The validator should detect these API groups as "cloud resources requiring tags":

```go
var CloudProviderAPIGroups = []string{
    // AWS (Upbound)
    ".aws.upbound.io",
    
    // Azure (Upbound)
    ".azure.upbound.io",
    
    // GCP (Upbound)
    ".gcp.upbound.io",
    
    // AWS (Crossplane contrib - legacy)
    ".aws.crossplane.io",
    
    // Azure (Crossplane contrib - legacy)
    ".azure.crossplane.io",
}
```

---

## Tag-Manager Input Schema Detection

The validator needs to understand `function-tag-manager` input:

```yaml
input:
  apiVersion: tag-manager.fn.crossplane.io/v1beta1
  kind: ManagedTags
  addTags:
    - type: FromValue
      tags:
        ManagedBy: "Crossplane"
        StampVersion: "super-nova"
    - type: FromCompositeFieldPath
      fromFieldPath: spec.parameters.tags  # ← This needs to be populated!
```

**Validation checks:**
1. If `FromValue` → extract static tags, check against required list
2. If `FromCompositeFieldPath` → verify the field path is populated by parent

---

## Benefits

1. **Prevent untagged resources** - Catch issues before `kubectl apply`
2. **Enforce tagging standards** - Required tags are validated
3. **Trace tag propagation** - See exactly where tags flow through hierarchy
4. **CI/CD integration** - Fail builds if tagging is broken

---

## Implementation Priority

1. **Phase 1:** Detect compositions without `function-tag-manager`
2. **Phase 2:** Check required tags in tag-manager config
3. **Phase 3:** Validate tag propagation through composition hierarchy
4. **Phase 4:** Show tag propagation tree visualization

---

## Example Validation Run

```bash
# Validate with tag checks
crossplane beta validate \
  ./compositionsV2 \
  --validate-tags \
  --required-tags=ManagedBy,StampName,Environment,StampVersion \
  --show-tag-analysis

# CI mode - fail on tag issues
crossplane beta validate \
  ./compositionsV2 \
  --validate-tags \
  --strict-mode  # Treat tag warnings as errors
```
