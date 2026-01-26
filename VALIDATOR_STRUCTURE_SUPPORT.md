# Validator Support for PhysicsX Composition Structure

This document explains how the Crossplane validator handles the PhysicsX hierarchical composition structure.

## Current Validator Capabilities

The validator already has the infrastructure to handle the PhysicsX structure:

### 1. Composition Tree Building

The validator builds a **dependency tree** automatically:

```go
// From composition_tree.go
type CompositionTree struct {
    roots     []*CompositionNode
    nodesByGVK map[schema.GroupVersionKind]*CompositionNode
    allNodes  []*CompositionNode
}

type CompositionNode struct {
    Name           string
    CompositeGVK   schema.GroupVersionKind
    Children       []*CompositionNode          // Child compositions
    ChildResources []ChildResourceInfo         // All child resources
    Patches        []PatchInfo
}

type ChildResourceInfo struct {
    Name        string
    GVK         schema.GroupVersionKind
    IsXR        bool              // True if this is another XR (dependency)
    Composition *CompositionNode  // Link to child composition node
}
```

**How it works:**
1. Parses all compositions
2. For each composition, identifies child resources
3. Detects which children are XRs (using `isXRGVK()`)
4. Links parent-child relationships
5. Identifies root compositions (not referenced by others)

### 2. Dependency Discovery

The validator automatically discovers dependencies:

**Example: PlatformStampV2 composition**
```yaml
resources:
  - name: common
    base:
      apiVersion: cloud.physicsx.ai/v1alpha1
      kind: StampCommonV2
```

**Validator detects:**
- `StampCommonV2` is an XR (has XRD)
- `PlatformStampV2` → `StampCommonV2` is a dependency
- Links them in the tree

**Example: StampCommonV2 composition**
```yaml
resources:
  - name: networking
    base:
      apiVersion: cloud.physicsx.ai/v1alpha1
      kind: StampNetworkingV2
  - name: cluster
    base:
      apiVersion: cloud.physicsx.ai/v1alpha1
      kind: StampClusterV2
```

**Validator detects:**
- `StampNetworkingV2` and `StampClusterV2` are XRs
- `StampCommonV2` → `StampNetworkingV2` dependency
- `StampCommonV2` → `StampClusterV2` dependency
- Links them in the tree

### 3. Status Chain Validation

The validator validates status field propagation:

```go
// From status_chain_validator.go
type StatusChainValidator struct {
    compositionsByXRKind map[string][]*ParsedComposition
    statusWrites         map[string][]StatusWrite
    statusReads          map[string][]StatusRead
    internalStatusReads  map[string][]StatusRead
}
```

**Validation process:**

1. **Index Status Writes**
   - Finds all `ToCompositeFieldPath` patches
   - Maps: Composition → status fields written

2. **Index Status Reads**
   - Finds all `FromCompositeFieldPath` patches reading from child XRs
   - Maps: Composition → status fields read from children

3. **Validate Chains**
   - For each read: verifies the child writes that field
   - For each write: verifies the XRD defines that field
   - Traces multi-level chains (child → parent → grandparent)

**Example validation:**

```
StampNetworkingV2 writes: status.vpcId
  ↓
StampCommonV2 reads: status.vpcId (from networking resource)
  ↓
Validator checks:
  ✅ StampNetworkingV2 composition has ToCompositeFieldPath writing status.vpcId
  ✅ StampNetworkingV2 XRD defines status.vpcId in schema
  ✅ StampCommonV2 composition reads status.vpcId from "networking" resource
  ✅ Types match
```

## How It Handles PhysicsX Structure

### PlatformStampV2 → StampCommonV2 → Dependencies

**Tree built:**
```
PlatformStampV2 (root)
└── StampCommonV2
    ├── StampNetworkingV2
    ├── StampClusterV2
    ├── StampIstioV2
    └── ... (more children)
```

**Status chain validation:**
1. **Level 1**: StampNetworkingV2 → StampCommonV2
   - Validates: StampNetworkingV2 writes `status.vpcId`
   - Validates: StampCommonV2 reads `status.vpcId` from networking

2. **Level 2**: StampCommonV2 → PlatformStampV2
   - Validates: StampCommonV2 writes `status.vpcId`
   - Validates: PlatformStampV2 reads `status.vpcId` from common

3. **Multi-level**: StampNetworkingV2 → StampCommonV2 → PlatformStampV2
   - Validates entire chain is complete

### Cross-Dependencies (Siblings)

**Example:**
- `StampExternalDNSV2` depends on `StampClusterV2.status.oidcIssuerUrl`
- Both are children of `StampCommonV2`

**How validator handles:**
- `StampCommonV2` reads `status.oidcIssuerUrl` from cluster
- `StampCommonV2` writes `status.oidcIssuerUrl` to its own status
- `StampExternalDNSV2` reads `status.oidcIssuerUrl` from StampCommonV2

**Validation:**
- ✅ Chain: StampClusterV2 → StampCommonV2 → StampExternalDNSV2
- ✅ Validates each link in the chain

## Current Validation Features

### ✅ Already Supported

1. **Dependency Discovery**
   - Automatically discovers all composition dependencies
   - Builds complete dependency tree
   - Identifies root compositions

2. **Status Chain Validation**
   - Validates child writes → parent reads
   - Validates multi-level chains
   - Validates XRD schema definitions
   - Validates type compatibility

3. **Patch Validation**
   - Validates `fromFieldPath` exists
   - Validates `toFieldPath` exists
   - Validates type compatibility

4. **Cross-Composition Dependencies**
   - Handles sibling dependencies via parent status
   - Validates multi-level propagation

### 🔍 How to Use

**Basic validation:**
```bash
crossplane beta validate \
  Stamp/PlatformStampV2/ \
  Stamp/StampCommonV2/ \
  Stamp/StampNetworkingV2/ \
  --validate-status-chains
```

**Validate entire structure:**
```bash
crossplane beta validate \
  Stamp/ \
  Tenant/ \
  --validate-status-chains \
  --verbose
```

**With CRD sources:**
```bash
crossplane beta validate \
  Stamp/ \
  --crd-sources "github:crossplane/crossplane:main:cluster/crds" \
  --crd-sources "k8s:v1.34.0" \
  --validate-status-chains
```

## Validation Output

### Tree Structure

The validator shows the dependency tree:

```
Composition Tree:
  PlatformStampV2 (root)
    → StampCommonV2
      → StampNetworkingV2
      → StampClusterV2
      → StampIstioV2
      → StampArgoCDV2
      ...
```

### Status Chain Issues

**Example error:**
```
❌ Status chain broken
  Composition: StampCommonV2
  Issue: Reads 'status.vpcId' from StampNetworkingV2 but the child never writes it
  File: Stamp/StampCommonV2/composition.yaml:87
```

**Example success:**
```
✅ Status chain valid
  Chain: StampNetworkingV2.status.vpcId → StampCommonV2.status.vpcId → PlatformStampV2.status.vpcId
```

## Limitations & Future Enhancements

### Current Limitations

1. **Composition Selectors**
   - Validator doesn't validate composition selector logic
   - Doesn't check if selector labels match composition labels
   - **Workaround**: Manual review of selectors

2. **Conditional Dependencies**
   - Doesn't validate conditional dependencies (e.g., AWS-only vs Azure-only)
   - **Workaround**: Validate each cloud variant separately

3. **Pipeline Functions**
   - Doesn't validate function inputs/outputs
   - **Note**: `--validate-function-inputs` flag exists but may need enhancement

### Potential Enhancements

1. **Composition Selector Validation**
   - Validate selector labels match composition labels
   - Detect missing compositions for selectors

2. **Cloud-Specific Validation**
   - Validate AWS vs Azure compositions separately
   - Detect cloud-specific field usage

3. **Dependency Ordering**
   - Validate creation order (networking → cluster → services)
   - Validate deletion order (services → cluster → networking)

## Summary

The validator **already supports** the PhysicsX hierarchical structure:

✅ **Automatic dependency discovery** - Finds all parent-child relationships  
✅ **Status chain validation** - Validates multi-level status propagation  
✅ **Tree building** - Builds complete dependency graph  
✅ **Cross-composition validation** - Handles sibling dependencies  

The validator should work out-of-the-box with the PhysicsX composition structure. The key is ensuring:
1. All XRDs are loaded (via `--crd-sources`)
2. All compositions are provided
3. `--validate-status-chains` flag is used

For the PhysicsX use case, the validator will:
- Discover PlatformStampV2 → StampCommonV2 → dependencies
- Validate status chains like `status.vpcId` propagation
- Report any broken chains or missing fields
