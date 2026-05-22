#!/usr/bin/env bash
# Build the image and push it to the ECR repo created by Terraform.
#
#   ECR_URL=$(terraform -chdir=deploy/aws output -raw ecr_repository_url) \
#   REGION=us-east-1 TAG=2.0.0 ./deploy/aws/push_image.sh
set -euo pipefail

: "${ECR_URL:?Set ECR_URL (terraform output ecr_repository_url)}"
REGION="${REGION:-us-east-1}"
TAG="${TAG:-2.0.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REGISTRY="${ECR_URL%%/*}"

echo "==> ECR login: $REGISTRY"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"

echo "==> Build $ECR_URL:$TAG"
docker build -t "$ECR_URL:$TAG" "$ROOT"

echo "==> Push"
docker push "$ECR_URL:$TAG"
echo "Done. ECS will pull $ECR_URL:$TAG on the next task placement."
