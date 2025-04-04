#!/bin/bash
set -e

# Configuration
IMAGE_NAME="devshahriar/go-test-server"
TAG="v1.0.0"

# Build the Docker image with platform flag
echo "Building Docker image: ${IMAGE_NAME}:${TAG}"
docker build --platform linux/amd64 -t ${IMAGE_NAME}:${TAG} -f cmd/test-server/Dockerfile .

# Push the Docker image
echo "Pushing Docker image: ${IMAGE_NAME}:${TAG}"
docker push ${IMAGE_NAME}:${TAG}

echo "Image built and pushed successfully: ${IMAGE_NAME}:${TAG}" 