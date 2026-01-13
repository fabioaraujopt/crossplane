# Crossplane Composition Validator (PhysicsX Fork)

This is a fork of [Crossplane](https://github.com/crossplane/crossplane) maintained by PhysicsX for the **Composition Validator** tool.

## Why This Fork?

We've developed an enhanced `crossplane beta validate` command with additional features for validating Crossplane Compositions:

### Features Added

1. **Comprehensive Patch Validation**
   - Validates `fromFieldPath` and `toFieldPath` exist in their respective schemas
   - Catches typos in patch paths before runtime errors

2. **Unused Parameter Detection**
   - Identifies XRD parameters defined but never used in composition patches
   - Helps eliminate dead configuration code

3. **Status Chain Validation** (`--validate-status-chains`)
   - Validates status field propagation through composition hierarchies
   - Ensures parent compositions correctly read from child XR status fields

4. **CRD Source Discovery** (`--crd-sources`)
   - Fetch CRDs from GitHub repos, local directories, or the Datree catalog
   - Parallel fetching for fast downloads (10+ concurrent connections)
   - Automatic caching of downloaded CRDs

5. **Function Input Validation** (`--validate-function-inputs`)
   - Downloads function packages and validates pipeline inputs against their schemas

6. **Strict Mode** (`--strict-mode`)
   - Treats warnings as errors for CI/CD pipelines

## Usage

```bash
# Basic validation
crossplane beta validate extensions/ resources/

# With all CRD sources
crossplane beta validate extensions/ resources/ \
  --crd-sources "github:crossplane/crossplane:main:cluster/crds" \
  --crd-sources "github:crossplane-contrib/provider-upjet-aws:main:package/crds" \
  --crd-sources "github:upbound/provider-vault:main:package/crds" \
  --crd-sources "k8s:v1.34.0" \
  --validate-status-chains \
  --only-invalid
```

## Docker Image

The validator is available as a Docker image from ECR:

```bash
docker pull 585768152950.dkr.ecr.us-east-1.amazonaws.com/crossplane-validator:latest
```

The image pre-caches 2000+ CRDs for instant validation.

## CI/CD Integration

This fork includes a GitHub Action that builds and pushes the validator image on every push to `main`:

- **Workflow:** `.github/workflows/build-validator.yaml`
- **Runs on:** Native amd64 (no QEMU emulation issues)
- **Caches:** Docker layers for fast builds

## Kept Workflows

- `ci.yml` - Original Crossplane CI tests
- `build-validator.yaml` - Our validator image build

## Upstream

This fork is based on [crossplane/crossplane](https://github.com/crossplane/crossplane).
Changes specific to PhysicsX are in:
- `cmd/crank/beta/validate/` - Enhanced validation logic
- `Dockerfile.validator` - Docker image with pre-cached CRDs
- `.github/workflows/build-validator.yaml` - CI/CD for the validator

## License

Apache 2.0 (same as upstream Crossplane)
