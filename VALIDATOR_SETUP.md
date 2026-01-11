# Crossplane Composition Validator - Setup Guide

This guide explains how to build, push, and use the custom Crossplane composition validator in CI/CD.

## 🎯 What This Does

Your custom fork includes a **comprehensive composition validator** that:
- ✅ Validates status field propagation through nested composition hierarchies
- ✅ Catches broken chains, missing XRD definitions, and orphaned status writes
- ✅ Detects internal status usage patterns
- ✅ Handles provider-specific fields correctly

See [STATUS_CHAIN_VALIDATION.md](./cmd/crank/beta/validate/STATUS_CHAIN_VALIDATION.md) for detailed implementation docs.

## 📦 Building and Pushing to ECR

### Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Docker** installed and running
3. **ECR repository** created (name: `crossplane-validator`)

### Step 1: Create ECR Repository (if not exists)

```bash
# Set your AWS region
export AWS_REGION=us-east-1  # Change as needed
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create ECR repository
aws ecr create-repository \
  --repository-name crossplane-validator \
  --region $AWS_REGION \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=AES256

# Set lifecycle policy to keep only last 10 images
aws ecr put-lifecycle-policy \
  --repository-name crossplane-validator \
  --region $AWS_REGION \
  --lifecycle-policy-text '{
    "rules": [{
      "rulePriority": 1,
      "description": "Keep last 10 images",
      "selection": {
        "tagStatus": "any",
        "countType": "imageCountMoreThan",
        "countNumber": 10
      },
      "action": {
        "type": "expire"
      }
    }]
  }'
```

### Step 2: Build and Push the Validator Image

```bash
# Navigate to the crossplane fork directory
cd /path/to/crossplane

# Authenticate Docker to ECR
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Build the Docker image
docker build \
  -f Dockerfile.validator \
  -t crossplane-validator:latest \
  -t crossplane-validator:$(git rev-parse --short HEAD) \
  .

# Tag for ECR
docker tag crossplane-validator:latest \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest

docker tag crossplane-validator:$(git rev-parse --short HEAD) \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:$(git rev-parse --short HEAD)

# Push to ECR
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:$(git rev-parse --short HEAD)
```

### Step 3: Verify the Image

```bash
# List images in ECR
aws ecr describe-images \
  --repository-name crossplane-validator \
  --region $AWS_REGION \
  --output table

# Test the image locally
docker run --rm \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest \
  beta validate --help
```

## 🔄 Updating the Validator

When you make changes to the validator code:

```bash
cd /path/to/crossplane

# Pull latest changes
git pull origin feature/comprehensive-composition-validator

# Rebuild and push
docker build -f Dockerfile.validator -t crossplane-validator:latest .

docker tag crossplane-validator:latest \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest

docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest
```

## 🤖 GitHub Actions Setup

### Required Secrets

Configure these secrets in your infrastructure repository:

1. **`AWS_ROLE_ARN`**: IAM role ARN for GitHub Actions OIDC authentication
   ```
   arn:aws:iam::YOUR_ACCOUNT_ID:role/github-actions-role
   ```

2. **`AWS_REGION`**: Your AWS region
   ```
   us-east-1
   ```

### IAM Role Policy

The GitHub Actions role needs these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeImages",
        "ecr:ListImages"
      ],
      "Resource": "arn:aws:ecr:REGION:ACCOUNT_ID:repository/crossplane-validator"
    }
  ]
}
```

### Trust Policy (OIDC)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/your-infra-repo:*"
        }
      }
    }
  ]
}
```

## 🚀 How It Works

### Workflow Trigger

The validation runs automatically when:
- A PR is opened/updated with changes to `crossplane/compositionsV2/**/*.yaml`
- Changes are pushed to `main` branch affecting compositions

### Validation Process

1. **Detects Changed Files**: Identifies which composition files were modified
2. **Pulls Validator Image**: Gets the latest validator from ECR
3. **Runs Validation**: Executes comprehensive validation including:
   - Schema validation
   - Status chain validation
   - Patch type validation
   - Cross-composition dependency checks
4. **Reports Results**: Comments on PR with results and creates job summary

### Sample Output

**✅ Success:**
```
Validation Summary:
✓ 45 compositions validated
✓ 234 status chains verified
✓ 0 errors, 0 warnings
```

**❌ Failure:**
```
❌ Error: Status chain broken
  Composition: XRParent
  Issue: Reads 'status.vpcId' from XRChild but the child never writes it
  File: compositions/XRParent/composition.yaml:123
```

## 🧪 Testing Locally

Test the validator before pushing changes:

```bash
cd /path/to/your-infra-repo/crossplane/compositionsV2

# Using local Docker image
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest \
  beta validate \
    extensions.yaml \
    functions.yaml \
    Stamp/ \
    Tenant/ \
    --validate-status-chains \
    --verbose

# Or using the local crossplane binary (if built)
cd /path/to/crossplane
go run ./cmd/crank beta validate \
  /path/to/your-infra-repo/crossplane/compositionsV2/extensions.yaml \
  /path/to/your-infra-repo/crossplane/compositionsV2/functions.yaml \
  /path/to/your-infra-repo/crossplane/compositionsV2/Stamp/ \
  /path/to/your-infra-repo/crossplane/compositionsV2/Tenant/ \
  --validate-status-chains
```

## 📋 Validation Features

### Status Chain Validation

Traces status field propagation through nested compositions:
- ✅ Validates status writes have corresponding XRD fields
- ✅ Ensures child compositions provide status fields that parents read
- ✅ Detects orphaned status writes (dead code)
- ✅ Handles internal status usage patterns
- ✅ Supports provider-specific fields

### Other Validations

- Schema compliance with XRDs
- Patch type mismatches
- Composition selector validation
- Nested schema validation
- Unknown field detection

## 🔧 Troubleshooting

### Image Pull Fails

```bash
# Check if image exists
aws ecr describe-images \
  --repository-name crossplane-validator \
  --region $AWS_REGION

# Re-authenticate Docker
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
```

### Validation Fails Unexpectedly

```bash
# Run with verbose output
docker run --rm \
  -v $(pwd):/workspace \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest \
  beta validate ... --verbose

# Check validator version
docker run --rm \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest \
  version
```

## 📚 Additional Resources

- [Crossplane Validation Documentation](https://github.com/crossplane/crossplane/tree/main/cmd/crank/beta/validate)
- [Status Chain Validation Details](./cmd/crank/beta/validate/STATUS_CHAIN_VALIDATION.md)
- [GitHub Actions Workflow](.github/workflows/validate-compositions.yaml)

## 🎯 Quick Reference Commands

```bash
# Build
docker build -f Dockerfile.validator -t crossplane-validator:latest .

# Tag
docker tag crossplane-validator:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest

# Push
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest

# Test
docker run --rm -v $(pwd):/workspace \
  $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/crossplane-validator:latest \
  beta validate extensions.yaml functions.yaml Stamp/ Tenant/ --validate-status-chains
```
