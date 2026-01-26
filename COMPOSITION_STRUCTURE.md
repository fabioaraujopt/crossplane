# Composition Structure for Validation

This document explains the hierarchical composition structure used in the PhysicsX Crossplane compositions that the validator needs to understand.

## Architecture Overview

The compositions follow a **layered, hierarchical architecture** with clear parent-child relationships:

```
┌─────────────────────────────────────────────────────────────┐
│                    PlatformStampV2 (Claim/XR)                │
│              (User creates this - top level)                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              PlatformStampV2 Composition                    │
│         (composition-aws.yaml / composition-azure.yaml)     │
│                                                              │
│  Resources:                                                  │
│    - StampCommonV2 (dependency)                             │
│    - StampS3AccessLogsV2 (AWS-only)                         │
│    - StampAWSLBControllerV2 (AWS-only)                      │
│    - StampKarpenterV2 (AWS-only)                            │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  StampCommonV2 (XR)                          │
│         (composition.yaml - cloud-agnostic)                 │
│                                                              │
│  Resources (dependencies):                                  │
│    - StampNetworkingV2 (writes: status.vpcId,              │
│                              status.privateSubnet1Id, etc.) │
│    - StampClusterV2 (writes: status.clusterEndpoint,       │
│                            status.oidcIssuerUrl, etc.)      │
│    - StampIstioV2                                           │
│    - StampArgoCDV2                                          │
│    - StampExternalDNSV2                                     │
│    - StampCertManagerV2                                     │
│    - StampJuiceFSV2                                         │
│    - StampVaultV2                                           │
│    - StampExternalSecretsV2                                 │
│    - StampCrossplaneV2                                       │
│    - ... (many more)                                        │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts

### 1. Claim to Platform Stamp

**User creates:**
```yaml
apiVersion: cloud.physicsx.ai/v1alpha1
kind: PlatformStampV2
metadata:
  name: my-platform
spec:
  compositionSelector:
    matchLabels:
      provider: aws
  parameters:
    clusterName: my-platform
    region: eu-west-2
    # ... more parameters
```

**PlatformStampV2 composition references:**
```yaml
resources:
  - name: common
    base:
      apiVersion: cloud.physicsx.ai/v1alpha1
      kind: StampCommonV2
      spec:
        parameters:
          cloud: aws
          # ... parameters passed down
```

### 2. Platform Stamp to Dependencies

**PlatformStampV2 composition** (`composition-aws.yaml`) creates:
- `StampCommonV2` (shared resources)
- `StampS3AccessLogsV2` (AWS-specific)
- `StampAWSLBControllerV2` (AWS-specific)
- `StampKarpenterV2` (AWS-specific)

**These are all dependencies** of the PlatformStampV2 composition.

### 3. StampCommonV2 to Its Dependencies

**StampCommonV2 composition** (`composition.yaml`) creates many child compositions:
- `StampNetworkingV2` - VPC/VNet
- `StampClusterV2` - EKS/AKS cluster
- `StampIstioV2` - Service mesh
- `StampArgoCDV2` - GitOps
- `StampExternalDNSV2` - DNS management
- `StampCertManagerV2` - TLS certificates
- ... and many more

**Each of these is a dependency** of StampCommonV2.

## Status Chain Validation

The validator must understand **status field propagation** through this hierarchy:

### Example 1: VPC ID Chain

```
StampNetworkingV2 (child)
  └─ writes: status.vpcId
       │
       ▼
StampCommonV2 (parent)
  └─ reads: status.vpcId (from networking resource)
       │
       ▼
PlatformStampV2 (top-level)
  └─ reads: status.vpcId (from common resource)
```

**Validation checks:**
1. ✅ `StampNetworkingV2` composition has a `ToCompositeFieldPath` patch writing `status.vpcId`
2. ✅ `StampNetworkingV2` XRD defines `status.vpcId` in its schema
3. ✅ `StampCommonV2` composition reads `status.vpcId` from the networking resource
4. ✅ `StampCommonV2` XRD defines `status.vpcId` in its schema
5. ✅ `PlatformStampV2` composition reads `status.vpcId` from the common resource

### Example 2: Cluster Endpoint Chain

```
StampClusterV2 (child)
  └─ writes: status.clusterEndpoint
       │
       ▼
StampCommonV2 (parent)
  └─ reads: status.clusterEndpoint (from cluster resource)
       │
       ▼
PlatformStampV2 (top-level)
  └─ may read: status.clusterEndpoint (from common resource)
```

### Example 3: OIDC Issuer Chain

```
StampClusterV2 (child)
  └─ writes: status.oidcIssuerUrl
       │
       ▼
StampCommonV2 (parent)
  └─ reads: status.oidcIssuerUrl (from cluster resource)
       │
       ▼
StampExternalDNSV2 (sibling, also child of StampCommonV2)
  └─ reads: status.oidcIssuerUrl (from StampCommonV2)
```

## Composition Dependency Graph

The validator needs to build a **dependency graph** to understand relationships:

```
PlatformStampV2
├── StampCommonV2
│   ├── StampNetworkingV2
│   ├── StampClusterV2
│   ├── StampIstioV2
│   ├── StampArgoCDV2
│   ├── StampExternalDNSV2 (depends on: StampClusterV2.status.oidcIssuerUrl)
│   ├── StampCertManagerV2 (depends on: StampClusterV2.status.oidcIssuerUrl)
│   ├── StampJuiceFSV2
│   ├── StampVaultV2
│   ├── StampExternalSecretsV2
│   ├── StampCrossplaneV2
│   └── ... (more dependencies)
├── StampS3AccessLogsV2 (AWS-only)
├── StampAWSLBControllerV2 (AWS-only, depends on: StampCommonV2)
└── StampKarpenterV2 (AWS-only, depends on: StampClusterV2)
```

## Key Validation Requirements

### 1. Dependency Resolution

The validator must:
- ✅ Discover all compositions referenced in a composition's resources
- ✅ Resolve XRD schemas for each referenced composition
- ✅ Build a dependency graph showing parent-child relationships
- ✅ Detect circular dependencies

### 2. Status Chain Validation

For each status field read:
- ✅ Verify the child composition writes that field
- ✅ Verify the child XRD defines that field in status schema
- ✅ Verify the parent composition reads from the correct resource name
- ✅ Verify type compatibility (string → string, etc.)

### 3. Patch Validation

For each patch:
- ✅ Verify `fromFieldPath` exists in source schema
- ✅ Verify `toFieldPath` exists in target schema
- ✅ Verify type compatibility
- ✅ Verify required fields are not optional

### 4. Cross-Composition Dependencies

The validator must understand:
- ✅ Sibling dependencies (e.g., `StampExternalDNSV2` depends on `StampClusterV2.status.oidcIssuerUrl`)
- ✅ Multi-level dependencies (e.g., `PlatformStampV2` → `StampCommonV2` → `StampClusterV2`)
- ✅ Conditional dependencies (AWS-only vs Azure-only)

## Real-World Examples

### Example: PlatformStampV2 → StampCommonV2

**PlatformStampV2 composition reads:**
```yaml
- fromFieldPath: status.vpcId
  toFieldPath: spec.parameters.vpcId
  type: FromCompositeFieldPath
```

**This means:**
- PlatformStampV2 expects `StampCommonV2` to have `status.vpcId`
- StampCommonV2 must write `status.vpcId` to its own status
- StampCommonV2 gets `status.vpcId` from `StampNetworkingV2`

### Example: StampCommonV2 → StampClusterV2

**StampCommonV2 composition reads:**
```yaml
- fromFieldPath: status.clusterEndpoint
  toFieldPath: status.clusterEndpoint
  type: ToCompositeFieldPath
```

**This means:**
- StampCommonV2 reads `status.clusterEndpoint` from the `cluster` resource (StampClusterV2)
- StampCommonV2 writes it to its own status
- PlatformStampV2 can then read it from StampCommonV2

### Example: StampExternalDNSV2 depends on StampClusterV2

**StampExternalDNSV2 needs OIDC info:**
```yaml
- fromFieldPath: status.oidcIssuerUrl
  toFieldPath: spec.parameters.oidcIssuerUrl
  type: FromCompositeFieldPath
```

**But it reads from StampCommonV2, not directly from StampClusterV2:**
- StampClusterV2 writes `status.oidcIssuerUrl`
- StampCommonV2 reads it and writes to its own status
- StampExternalDNSV2 reads from StampCommonV2

## Validation Flow

When validating `PlatformStampV2`:

1. **Load PlatformStampV2 composition**
   - Parse `composition-aws.yaml` or `composition-azure.yaml`
   - Identify all resources (dependencies)

2. **Resolve Dependencies**
   - For each resource, find its XRD
   - Find the composition that will be used
   - Recursively resolve child dependencies

3. **Build Dependency Graph**
   - PlatformStampV2 → StampCommonV2 → StampNetworkingV2
   - PlatformStampV2 → StampCommonV2 → StampClusterV2
   - PlatformStampV2 → StampCommonV2 → StampIstioV2
   - etc.

4. **Validate Status Chains**
   - For each `FromCompositeFieldPath` reading status:
     - Find the source resource
     - Verify the source composition writes that field
     - Verify the source XRD defines that field
     - Verify type compatibility

5. **Validate Patches**
   - Verify all `fromFieldPath` exist
   - Verify all `toFieldPath` exist
   - Verify type compatibility

6. **Report Issues**
   - Broken status chains
   - Missing fields
   - Type mismatches
   - Circular dependencies

## Directory Structure

```
compositionsV2/
├── Stamp/
│   ├── PlatformStampV2/          # Top-level orchestrator
│   │   ├── compositeresourcedefinition.yaml
│   │   ├── composition-aws.yaml
│   │   └── composition-azure.yaml
│   ├── StampCommonV2/            # Shared resources
│   │   ├── compositeresourcedefinition.yaml
│   │   └── composition.yaml
│   ├── StampNetworkingV2/        # Dependency of StampCommonV2
│   ├── StampClusterV2/           # Dependency of StampCommonV2
│   ├── StampIstioV2/             # Dependency of StampCommonV2
│   └── ... (many more)
└── Tenant/
    ├── TenantV2/                  # Top-level tenant orchestrator
    ├── TenantCommonV2/            # Shared tenant resources
    └── ... (tenant dependencies)
```

## Key Takeaways for Validator

1. **Hierarchical Structure**: Claims → Platform Stamps → Common → Dependencies
2. **Status Propagation**: Child writes → Parent reads → Grandparent reads
3. **Cross-Dependencies**: Siblings can depend on each other via parent status
4. **Multi-Cloud**: Same structure, different implementations (aws vs azure)
5. **Composition Selectors**: Used to pick cloud-specific implementations

The validator must understand this entire structure to properly validate status chains, patch references, and cross-composition dependencies.
