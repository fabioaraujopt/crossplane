#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ECR_REPOSITORY="crossplane-validator"
DOCKERFILE="Dockerfile.validator"

echo -e "${BLUE}🚀 Crossplane Validator - Build & Push to ECR${NC}"
echo "=================================================="
echo ""

# Check prerequisites
command -v aws >/dev/null 2>&1 || { echo -e "${RED}❌ AWS CLI is required but not installed.${NC}" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo -e "${RED}❌ Docker is required but not installed.${NC}" >&2; exit 1; }

# Get AWS account ID and region
echo -e "${YELLOW}📋 Gathering AWS information...${NC}"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=${AWS_REGION:-us-east-1}

echo "  Account ID: $AWS_ACCOUNT_ID"
echo "  Region: $AWS_REGION"
echo ""

# Get git commit hash for tagging
GIT_COMMIT=$(git rev-parse --short HEAD)
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD | tr '/' '-')
LOCAL_ARCH=$(uname -m)

echo -e "${YELLOW}🏷️  Image tags:${NC}"
echo "  - latest"
echo "  - $GIT_COMMIT"
echo "  - $GIT_BRANCH"
echo ""

# Check if ECR repository exists
echo -e "${YELLOW}🔍 Checking ECR repository...${NC}"
if ! aws ecr describe-repositories --repository-names "$ECR_REPOSITORY" --region "$AWS_REGION" >/dev/null 2>&1; then
    echo -e "${RED}❌ ECR repository '$ECR_REPOSITORY' does not exist.${NC}"
    echo ""
    read -p "Create it now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}📦 Creating ECR repository...${NC}"
        aws ecr create-repository \
            --repository-name "$ECR_REPOSITORY" \
            --region "$AWS_REGION" \
            --image-scanning-configuration scanOnPush=true \
            --encryption-configuration encryptionType=AES256
        echo -e "${GREEN}✅ Repository created${NC}"
    else
        echo -e "${RED}Aborted.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ Repository exists${NC}"
fi
echo ""

# Authenticate Docker to ECR
echo -e "${YELLOW}🔐 Authenticating Docker to ECR...${NC}"
aws ecr get-login-password --region "$AWS_REGION" | \
    docker login --username AWS --password-stdin \
    "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
echo -e "${GREEN}✅ Authenticated${NC}"
echo ""

# Build the Docker image for amd64 (for GitHub Actions/Linux)
# Uses Go's native cross-compilation - no slow QEMU emulation!
echo -e "${YELLOW}🔨 Building Docker image for linux/amd64 (using Go cross-compilation)...${NC}"
docker buildx build \
    --platform linux/amd64 \
    --load \
    -f "$DOCKERFILE" \
    -t "$ECR_REPOSITORY:latest" \
    -t "$ECR_REPOSITORY:$GIT_COMMIT" \
    -t "$ECR_REPOSITORY:$GIT_BRANCH" \
    .
echo -e "${GREEN}✅ Build completed (linux/amd64)${NC}"
echo ""

# Also build for local platform for testing
if [ "$LOCAL_ARCH" = "arm64" ]; then
    echo -e "${YELLOW}🔨 Building local test image for arm64...${NC}"
    docker buildx build \
        --platform linux/arm64 \
        --load \
        -f "$DOCKERFILE" \
        -t "$ECR_REPOSITORY:local-test" \
        .
    echo -e "${GREEN}✅ Local test image built (linux/arm64)${NC}"
    echo ""
fi

# Tag for ECR
echo -e "${YELLOW}🏷️  Tagging images for ECR...${NC}"
ECR_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY"

docker tag "$ECR_REPOSITORY:latest" "$ECR_URI:latest"
docker tag "$ECR_REPOSITORY:$GIT_COMMIT" "$ECR_URI:$GIT_COMMIT"
docker tag "$ECR_REPOSITORY:$GIT_BRANCH" "$ECR_URI:$GIT_BRANCH"
echo -e "${GREEN}✅ Tagged${NC}"
echo ""

# Push to ECR
echo -e "${YELLOW}📤 Pushing images to ECR...${NC}"
echo "  Pushing: $ECR_URI:latest"
docker push "$ECR_URI:latest"

echo "  Pushing: $ECR_URI:$GIT_COMMIT"
docker push "$ECR_URI:$GIT_COMMIT"

echo "  Pushing: $ECR_URI:$GIT_BRANCH"
docker push "$ECR_URI:$GIT_BRANCH"

echo -e "${GREEN}✅ Push completed${NC}"
echo ""

# List images in ECR
echo -e "${YELLOW}📋 Current images in ECR:${NC}"
aws ecr describe-images \
    --repository-name "$ECR_REPOSITORY" \
    --region "$AWS_REGION" \
    --query 'sort_by(imageDetails,& imagePushedAt)[-5:].[imageTags[0],imagePushedAt,imageSizeInBytes]' \
    --output table
echo ""

# Test the image
echo -e "${YELLOW}🧪 Testing the image...${NC}"
if [ "$LOCAL_ARCH" = "arm64" ] && docker image inspect "$ECR_REPOSITORY:local-test" >/dev/null 2>&1; then
    echo "  (Testing local arm64 build - ECR image is amd64 for GitHub Actions)"
    docker run --rm "$ECR_REPOSITORY:local-test" version || \
        docker run --rm "$ECR_REPOSITORY:local-test" --help | head -20
else
    docker run --rm "$ECR_URI:latest" version || \
        docker run --rm "$ECR_URI:latest" --help | head -20 || \
        echo -e "${YELLOW}⚠️  Cannot test amd64 image on arm64 Mac (will work in GitHub Actions)${NC}"
fi

echo ""
echo -e "${GREEN}✅ SUCCESS! Validator image pushed to ECR${NC}"
echo ""
echo -e "${BLUE}📝 Image URIs:${NC}"
echo "  Latest:  $ECR_URI:latest"
echo "  Commit:  $ECR_URI:$GIT_COMMIT"
echo "  Branch:  $ECR_URI:$GIT_BRANCH"
echo ""
echo -e "${BLUE}🚀 Next steps:${NC}"
echo "  1. The GitHub Actions workflow will automatically use this image"
echo "  2. Test locally: docker run --rm -v \$(pwd):/workspace $ECR_URI:latest beta validate --help"
echo "  3. See VALIDATOR_SETUP.md for more details"
