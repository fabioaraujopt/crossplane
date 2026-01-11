# Crossplane Composition Validator

A comprehensive validation tool for Crossplane Compositions, XRDs, and related resources. This validator catches errors **before deployment**, preventing runtime failures.

## Quick Start

```bash
# Basic validation
go run ./cmd/crank beta validate \
  /path/to/compositions \
  /path/to/compositions \
  --only-invalid

# With CRD sources for full schema validation
go run ./cmd/crank beta validate \
  /path/to/compositions \
  /path/to/compositions \
  --crd-sources "github:crossplane/crossplane:main:cluster/crds" \
  --crd-sources "github:crossplane-contrib/provider-upjet-aws:main:package/crds" \
  --crd-sources "github:crossplane-contrib/provider-upjet-azure:main:package/crds" \
  --crd-sources "github:crossplane-contrib/provider-helm:main:package/crds" \
  --crd-sources "github:crossplane-contrib/provider-kubernetes:main:package/crds" \
  --crd-sources "github:upbound/provider-vault:main:package/crds" \
  --crd-sources "catalog:https://raw.githubusercontent.com/datreeio/CRDs-catalog/main" \
  --crd-sources "k8s:v1.29.0" \
  --validate-function-inputs \
  --only-invalid
```

## CRD Source Types

The validator supports multiple CRD source types, all configurable via `--crd-sources`:

| Source Type | Format | Example |
|-------------|--------|---------|
| **GitHub** | `github:org/repo:branch:path` | `github:crossplane-contrib/provider-upjet-aws:main:package/crds` |
| **Catalog** | `catalog:https://url` | `catalog:https://raw.githubusercontent.com/datreeio/CRDs-catalog/main` |
| **K8s Core** | `k8s:version` | `k8s:v1.29.0` |
| **Local** | `local:/path` or `/path` | `local:/home/user/crds` |
| **Cluster** | `cluster` | `cluster` (uses kubeconfig) |

### K8s Core Types

Core Kubernetes types (Secret, ConfigMap, Service, etc.) don't have CRDs. Use `k8s:v1.29.0` to fetch JSON schemas from [kubernetes-json-schema](https://github.com/yannh/kubernetes-json-schema) and convert them to CRD format for validation.

**Supported core types:**
- `v1`: Secret, ConfigMap, Namespace, Service, ServiceAccount, PersistentVolumeClaim
- `apps/v1`: Deployment, StatefulSet, DaemonSet, ReplicaSet
- `batch/v1`: Job, CronJob
- `rbac.authorization.k8s.io/v1`: Role, RoleBinding, ClusterRole, ClusterRoleBinding
- `networking.k8s.io/v1`: Ingress, NetworkPolicy, IngressClass
- `storage.k8s.io/v1`: StorageClass
- `scheduling.k8s.io/v1`: PriorityClass
- `policy/v1`: PodDisruptionBudget
- `admissionregistration.k8s.io/v1`: MutatingWebhookConfiguration, ValidatingWebhookConfiguration

## CLI Flags

| Flag | Description |
|------|-------------|
| `--only-invalid` | Only show errors, hide success messages |
| `--validate-patches` | Validate patch paths against schemas |
| `--detect-unused-params` | Find XRD parameters not used in patches |
| `--validate-function-inputs` | Download function packages and validate inputs |
| `--crd-sources` | CRD sources for schema validation (repeatable) |
| `--fail-on-missing-crd` | Exit with error if CRDs not found |
| `--clean-crd-cache` | Force re-download of cached CRDs |
| `--use-cluster` | Fetch CRDs from live cluster |
| `--kubeconfig` | Path to kubeconfig (for cluster mode) |
| `--kube-context` | Kubernetes context to use |
| `--strict-mode` | Treat warnings as errors |
| `--show-tree` | Show composition hierarchy |
| `--show-details` | Show detailed error messages |

---

## What It Validates ✅

### 1. XRD Schema Validation

| Check | Example Error |
|-------|---------------|
| Invalid OpenAPI schema syntax | `type: strng` → should be `string` |
| Missing required properties | Missing `type` field in schema |
| Wrong enum values | Using `"staging"` when only `["dev", "prod"]` allowed |
| Invalid default values | `default: 123` for `type: string` |
| Duplicate property names | Same property defined twice |

### 2. Composition Structure Validation

| Check | Example Error |
|-------|---------------|
| Invalid `compositeTypeRef` | `kind: WrongName` not matching XRD |
| Invalid `mode` | `mode: Pipline` (typo) |
| Missing function reference | Empty `functionRef.name` |
| Invalid function input | `kind: Resourcess` (typo) |
| Wrong function API version | `pt.fn.crossplane.io/v1beta2` |

### 3. Patch Path Validation ⭐

**Most common error category.** Validates both `fromFieldPath` and `toFieldPath`:

| Check | Example Error |
|-------|---------------|
| Typo in source path | `spec.parameterss.region` |
| Typo in target path | `specs.forProvider.region` |
| Non-existent nested path | `spec.parameters.karpenter.nonExistent` |
| Invalid array index | `requirements[x].values` instead of `[0]` |
| Path into non-object | `spec.parameters.region.subfield` (region is string) |

### 4. Patch Type Validation

| Check | Example Error |
|-------|---------------|
| Invalid `type` enum | `type: FromCompositeFieldPaths` (typo) |
| Wrong policy value | `policy.fromFieldPath: Optionals` |
| Missing required fields | `CombineFromComposite` without `combine` |

### 5. Transform Validation

| Check | Example Error |
|-------|---------------|
| Invalid transform type | `type: convertt` |
| Invalid convert target | `convert.toType: stssring` |
| Invalid string type | `string.type: Formatt` |
| Invalid math operations | `multiply: "abc"` |

### 6. Base Resource Validation

| Check | Example Error |
|-------|---------------|
| Unknown fields | `enableAutoScaling` (deprecated/renamed) |
| Wrong API version | `iam.aws.upbound.io/v1beta2` (doesn't exist) |
| Nested manifest typos | `requirxxements` instead of `requirements` |
| Invalid field types | `minSize: "two"` instead of `2` |

### 7. Unused Parameter Detection

| Check | Example |
|-------|---------|
| XRD parameter never patched | `spec.parameters.karpenter.azure` defined but unused |
| Dead code parameters | Parameter exists in XRD but no composition uses it |

### 8. Function Input Schema Validation

When `--validate-function-inputs` is enabled:

| Check | Example Error |
|-------|---------------|
| Invalid function input structure | Wrong `resources` format |
| Invalid patch within function | Typos in function-specific patches |
| Missing required function fields | Required function parameters missing |

### 9. Composition Structure Validation ✨ NEW

| Check | Example Error |
|-------|---------------|
| Invalid `compositeTypeRef` | `kind: TestStampV3` when XRD defines `TestStampV2` |
| Non-existent PatchSet reference | `patchSetName: nonExistent` when PatchSet not defined |
| Unused PatchSet (warning) | PatchSet defined but never used in any resource |
| Duplicate `toFieldPath` (warning) | Multiple patches writing to same field |

### 10. Composition Selector Validation 🆕

Validates that child XRs with `compositionSelector.matchLabels` can find matching compositions.

| Check | Example Error |
|-------|---------------|
| Selector matches no composition | `provider: awsss` → no composition with that label |
| Wrong kind | Selector finds composition but for different XRD kind |
| Unused compositions (warning) | Composition has labels but is never selected |

**Note:** Dynamic selectors (labels patched from parameters) cannot be statically validated.

### 11. Patch Type Mismatch Validation 🆕

Validates that patch source and target field types are compatible.

| Check | Example Error |
|-------|---------------|
| Parameter type → target type | `string` → `integer` mismatch |
| Status type propagation | Parent reads `integer`, child writes `string` |
| With transforms | Respects `convert` transform type changes |

**Example:**
```yaml
# XRD defines: spec.parameters.count: type: string
# Target expects: spec.forProvider.instanceCount: type: integer
patches:
  - fromFieldPath: spec.parameters.count
    toFieldPath: spec.forProvider.instanceCount
    # ← ERROR: string → integer mismatch!
    # Fix: Add transform: { type: convert, convert: { toType: integer }}
```

### 12. Status Propagation Chain Validation 🔥

**Most important for hierarchical compositions.** Traces status field flow through composition chains.

| Check | Example Error |
|-------|---------------|
| Status write to undefined XRD field | Composition writes `status.vpcId` but XRD doesn't define it |
| Broken status chain | Parent reads `status.vpcId` from child, but child never writes it |
| Missing child XRD field | Parent reads field child XRD doesn't define |
| Unused status write (warning) | Composition writes status field no parent ever reads |

**Example of broken chain:**
```yaml
# XRParent (parent) tries to read:
- fromFieldPath: status.vpcId   # From XRChild child
  toFieldPath: status.vpcId

# But XRChild composition never writes to status.vpcId!
# Validator catches: "child composition never writes to this status field"
```

**See `STATUS_CHAIN_VALIDATION.md` for full details.**

---

## What It Doesn't Validate (Yet) ❌

### 1. Composition Selector Validation

**Problem:** Child compositions use `compositionSelector` to pick implementations:

```yaml
spec:
  crossplane:
    compositionSelector:
      matchLabels:
        provider: awss  # ← Typo, no matching composition!
```

**Impact:** Runtime failure - no composition matches.

### 2. Cross-Reference Selector Validation

**Problem:** Resources use `matchControllerRef` and `matchLabels` to reference each other:

```yaml
# Subnet trying to find its VPC
spec:
  forProvider:
    vpcIdSelector:
      matchControllerRef: true
      matchLabels:
        role: networrk  # ← Typo, nothing matches!
```

**Why Not Validated:**
- CRD schemas don't specify which Kind a selector targets (e.g., `vpcIdSelector` → VPC)
- This mapping is hardcoded in provider Go code, not exposed in CRDs
- Labels can be dynamically patched from parameters/status, making static validation unreliable
- Would require heuristics (field naming, description parsing) that are fragile

**Impact:** Resources don't connect at runtime, causing "no resource found" errors.

**Workaround:** Test in dev environment before production deployment.

### 3. Circular Dependency Detection

**Problem:** Resource A depends on B, B depends on A.

**Impact:** Infinite loop or deadlock at runtime.

### 4. Runtime Value Validation

**Problem:** Map transform keys that don't match input values:

```yaml
transforms:
  - type: map
    map:
      dev: "false"
      prod: "true"
      # Input is "staging" → no match!
```

**Impact:** Empty or null value at runtime.

---

## Error Categories by Severity

### 🔴 Critical (Causes deployment failure)
- Invalid schema syntax
- Non-existent patch paths
- Missing required fields
- Wrong API versions

### 🟠 High (Causes runtime issues)
- Broken status propagation
- Invalid selectors
- Missing PatchSets

### 🟡 Medium (Potential issues)
- Unused parameters (dead code)
- Deprecated fields

### 🟢 Low (Style/best practices)
- Inconsistent naming
- Missing descriptions

---

## Caching

CRD sources are cached locally to avoid repeated downloads:

- **Cache location:** `~/.crossplane/cache/crd-sources/`
- **Cache lifetime:** Indefinite (until manually cleared)
- **Clear cache:** `--clean-crd-cache`

```bash
# Force fresh download
go run ./cmd/crank beta validate \
  ./compositions ./compositions \
  --crd-sources "github:crossplane-contrib/provider-upjet-aws:main:package/crds" \
  --clean-crd-cache
```

---

## Example Output

```
=== CRD Source Discovery ===
Looking for 88 required CRDs from 8 sources...

[1/8] Checking crossplane-contrib/provider-upjet-aws (88 CRDs remaining)...
Loaded CRDs from cache: crossplane-contrib/provider-upjet-aws
    ✅ Found 36 CRDs
[2/8] Checking crossplane-contrib/provider-upjet-azure (52 CRDs remaining)...
    ✅ Found 19 CRDs
...
[8/8] Checking v1.29.0 (12 CRDs remaining)...
Fetching K8s schemas from kubernetes-json-schema (v1.29.0)...
    ✅ Found 12 CRDs

[✓] Found 88/88 required CRDs from sources

[x] composition-azure.yaml:125: unknown field: "enableAutoScaling"
[x] composition-azure.yaml:317: unknown field: "scopeSelector"
[x] composition-aws.yaml:1493: toFieldPath 'specs.forProvider...' invalid (at 'specs')

=== Validation Summary ===
Compositions analyzed: 68
Patches validated: 2826 (valid: 2824, invalid: 2)
Parameters analyzed: 355 (used: 342, unused: 13)
```

---

## Implementation Roadmap

Features ordered by difficulty (easiest first):

---

### 🟢 Phase 1: Easy Wins (1-2 hours each)

#### 1.1 PatchSet Reference Validation
**Status:** ✅ Implemented  
**Effort:** 🟢 Easy (1 hour)

**Problem:**
```yaml
patches:
  - type: PatchSet
    patchSetName: nonExistent  # ← Silently ignored!
```

**Implementation:**
```go
// In composition_parser.go
func (p *Parser) ValidatePatchSetReferences() []error {
    var errors []error
    for _, res := range p.composition.Resources {
        for _, patch := range res.Patches {
            if patch.Type == "PatchSet" {
                if _, ok := p.patchSets[patch.PatchSetName]; !ok {
                    errors = append(errors, fmt.Errorf(
                        "resource '%s' references non-existent PatchSet '%s'",
                        res.Name, patch.PatchSetName))
                }
            }
        }
    }
    return errors
}
```

---

#### 1.2 CompositeTypeRef Cross-Check
**Status:** ✅ Implemented  
**Effort:** 🟢 Easy (1 hour)

**Problem:**
```yaml
compositeTypeRef:
  kind: PlatformStampV3  # ← Typo! XRD defines PlatformStampV2
```

**Implementation:**
```go
// In cmd.go or new file: composition_xrd_validator.go
func ValidateCompositeTypeRefs(compositions, xrds []*unstructured.Unstructured) []error {
    xrdKinds := make(map[string]bool)
    for _, xrd := range xrds {
        kind, _, _ := unstructured.NestedString(xrd.Object, "spec", "names", "kind")
        xrdKinds[kind] = true
    }
    
    var errors []error
    for _, comp := range compositions {
        kind, _, _ := unstructured.NestedString(comp.Object, "spec", "compositeTypeRef", "kind")
        if kind != "" && !xrdKinds[kind] {
            errors = append(errors, fmt.Errorf(
                "composition '%s' references unknown XRD kind '%s'",
                comp.GetName(), kind))
        }
    }
    return errors
}
```

---

#### 1.3 Unused PatchSet Detection
**Status:** ✅ Implemented  
**Effort:** 🟢 Easy (1 hour)

**Problem:** PatchSets defined but never used (dead code).

**Implementation:**
```go
func DetectUnusedPatchSets(composition *ParsedComposition) []string {
    usedPatchSets := make(map[string]bool)
    for _, res := range composition.Resources {
        for _, patch := range res.Patches {
            if patch.Type == "PatchSet" {
                usedPatchSets[patch.PatchSetName] = true
            }
        }
    }
    
    var unused []string
    for name := range composition.PatchSets {
        if !usedPatchSets[name] {
            unused = append(unused, name)
        }
    }
    return unused
}
```

---

### 🟡 Phase 2: Medium Complexity (2-4 hours each)

#### 2.1 Type-Specific Patch Field Validation
**Status:** ✅ Implemented  
**Effort:** 🟡 Medium (2 hours)

**Problem:**
```yaml
- type: CombineFromComposite
  toFieldPath: spec.forProvider.name
  # Missing: combine.variables, combine.strategy!
```

**Implementation:**
```go
func ValidatePatchRequiredFields(patch Patch) []error {
    var errors []error
    
    switch patch.Type {
    case "CombineFromComposite", "CombineToComposite":
        if patch.Combine == nil {
            errors = append(errors, fmt.Errorf("'%s' requires 'combine' field", patch.Type))
        } else {
            if len(patch.Combine.Variables) == 0 {
                errors = append(errors, fmt.Errorf("'%s' requires 'combine.variables'", patch.Type))
            }
            if patch.Combine.Strategy == "" {
                errors = append(errors, fmt.Errorf("'%s' requires 'combine.strategy'", patch.Type))
            }
        }
    case "FromCompositeFieldPath", "ToCompositeFieldPath":
        if patch.FromFieldPath == "" {
            errors = append(errors, fmt.Errorf("'%s' requires 'fromFieldPath'", patch.Type))
        }
    }
    
    return errors
}
```

---

#### 2.2 Circular Dependency Detection
**Status:** Not Implemented  
**Effort:** 🟡 Medium (3 hours)

**Problem:** Resource A depends on B, B depends on A.

**Implementation:**
```go
type DependencyGraph struct {
    nodes map[string]bool
    edges map[string][]string // resource -> dependencies
}

func (g *DependencyGraph) DetectCycles() [][]string {
    // Use DFS with coloring (white/gray/black)
    // Gray nodes in current path = cycle
    var cycles [][]string
    color := make(map[string]int) // 0=white, 1=gray, 2=black
    
    var dfs func(node string, path []string) bool
    dfs = func(node string, path []string) bool {
        if color[node] == 1 { // Gray = cycle!
            cycles = append(cycles, append(path, node))
            return true
        }
        if color[node] == 2 { // Black = already processed
            return false
        }
        
        color[node] = 1 // Mark gray
        for _, dep := range g.edges[node] {
            dfs(dep, append(path, node))
        }
        color[node] = 2 // Mark black
        return false
    }
    
    for node := range g.nodes {
        if color[node] == 0 {
            dfs(node, nil)
        }
    }
    return cycles
}
```

---

#### 2.3 Cross-XRD Status Field Validation
**Status:** Partial  
**Effort:** 🟡 Medium (3 hours)

**Problem:** Parent reads `status.vpcId` from child, but child XRD doesn't define it.

**Implementation:**
```go
func ValidateCrossXRDStatusPaths(composition *ParsedComposition, xrds map[string]*XRDSchema) []error {
    var errors []error
    
    for _, res := range composition.Resources {
        childKind := res.Base.Kind
        childXRD := xrds[childKind]
        if childXRD == nil {
            continue // Can't validate without XRD
        }
        
        for _, patch := range res.Patches {
            if patch.Type == "ToCompositeFieldPath" {
                // patch.FromFieldPath should exist in child's status
                if !childXRD.HasStatusPath(patch.FromFieldPath) {
                    errors = append(errors, fmt.Errorf(
                        "resource '%s' reads '%s' from child '%s' but child XRD doesn't define it",
                        res.Name, patch.FromFieldPath, childKind))
                }
            }
        }
    }
    return errors
}
```

---

### 🔴 Phase 3: Hard (4-8 hours each)

#### 3.1 Status Propagation Chain Validation
**Status:** ✅ Implemented  
**Effort:** 🔴 Hard (6 hours)

**Problem:** Trace `XRPlatform → XRParent → XRChild` and verify status flows up.

**Implementation:**
```go
type StatusChain struct {
    source      string // e.g., "XRChild"
    path        string // e.g., "status.clusterEndpoint"
    propagation []struct {
        composition string
        fromPath    string
        toPath      string
    }
}

func TraceStatusPropagation(compositions map[string]*ParsedComposition) []StatusChain {
    // 1. Build graph of all ToCompositeFieldPath patches
    // 2. For each composition that writes to status, trace up
    // 3. Verify chain is complete to root
}

func ValidateStatusChains(chains []StatusChain, xrds map[string]*XRDSchema) []error {
    // For each chain, verify:
    // 1. Source actually writes the value
    // 2. Each intermediate propagates it
    // 3. Root XRD defines the field
}
```

---

#### 3.2 Composition Selector Validation
**Status:** ✅ Implemented  
**Effort:** 🔴 Hard (4 hours)

**Problem:** Child XR uses `compositionSelector.matchLabels.provider: awss` but no composition matches.

**What It Validates:**
- Static `matchLabels` in child resources
- Reports when selector matches no composition of the target kind
- Warns about compositions with labels that are never selected (potential dead code)

**Limitation:** Cannot validate **dynamic selectors** where labels are patched from parameters:
```yaml
# This cannot be statically validated:
- fromFieldPath: spec.parameters.cloud
  toFieldPath: spec.crossplane.compositionSelector.matchLabels.provider
```

---

#### 3.3 Cross-Reference Selector Validation
**Status:** ❌ Not Implementing (See Limitations)  
**Effort:** 🔴 Very Hard (8+ hours)

**Problem:** Validate `vpcIdSelector`, `subnetIdSelector`, etc. to ensure `matchLabels` match resources.

**Why Not Implemented:**
1. **No Schema Metadata:** CRDs don't specify which Kind a selector targets
2. **Runtime Labels:** Labels are often patched from parameters/status (not static)
3. **Provider-Specific:** Each provider hardcodes selector→Kind mapping in Go code
4. **Fragile Heuristics:** Would require parsing field names/descriptions (unreliable)

**Recommendation:** Test in dev environment; this validation requires runtime knowledge.

---

### 📊 Implementation Priority Matrix

| Feature | Effort | Impact | Priority | Status |
|---------|--------|--------|----------|--------|
| PatchSet Reference | 🟢 1h | High | ⭐⭐⭐⭐⭐ | ✅ Done |
| CompositeTypeRef Check | 🟢 1h | High | ⭐⭐⭐⭐⭐ | ✅ Done |
| Unused PatchSets | 🟢 1h | Medium | ⭐⭐⭐⭐ | ✅ Done |
| Metadata Field Validation | 🟢 1h | High | ⭐⭐⭐⭐⭐ | ✅ Done |
| Duplicate toFieldPath | 🟢 1h | Medium | ⭐⭐⭐⭐ | ✅ Done |
| Status Chain Validation | 🔴 6h | Very High | ⭐⭐⭐⭐⭐ | ✅ Done |
| Patch Required Fields | 🟡 2h | High | ⭐⭐⭐⭐ | ✅ Done |
| Patch Type Mismatch | 🟡 2h | High | ⭐⭐⭐⭐ | ✅ Done |
| Circular Dependencies | 🟡 3h | Medium | ⭐⭐⭐ | Pending |
| Cross-XRD Status | 🟡 3h | High | ⭐⭐⭐⭐ | Partial |
| Composition Selectors | 🔴 4h | High | ⭐⭐⭐⭐ | ✅ Done |
| Cross-Reference Selectors | 🔴 8h+ | Low | ⭐ | ❌ Not Implementing |

---

## Contributing

To add new validations:

1. **Schema validation:** Modify `validate.go`
2. **Patch validation:** Modify `patch_validator.go`
3. **New CRD sources:** Modify `crd_sources.go`
4. **Composition parsing:** Modify `composition_parser.go`

---

## Architecture

```
cmd/crank/beta/validate/
├── cmd.go                    # CLI entry point and flag handling
├── validate.go               # Schema validation logic
├── patch_validator.go        # Patch path validation
├── composition_parser.go     # Parse compositions and PatchSets
├── composition_validator.go  # Composition structure validation (typeRef, PatchSets)
├── schema_navigator.go       # Navigate OpenAPI schemas
├── crd_sources.go            # Fetch CRDs from various sources
├── cluster_discovery.go      # Fetch CRDs from live cluster
├── function_discovery.go     # Discover and download function schemas
├── base_validator.go         # Filter required field errors for base resources
├── validations_test.go       # Comprehensive test suite
└── README.md                 # This file
```
