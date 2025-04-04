#!/bin/bash

set -e

# Configuration
IMAGE_NAME="devshahriar/abproxy-agent"
TAG="v1.39.0"
NAMESPACE="monitoring"

echo "Building new ABProxy Agent image..."

# Build the Docker image
docker build -t ${IMAGE_NAME}:${TAG} .
docker push ${IMAGE_NAME}:${TAG}

echo "Image ${IMAGE_NAME}:${TAG} built and pushed."

# Update the DaemonSet to use the new image
kubectl -n ${NAMESPACE} set image daemonset/abproxy-agent abproxy-agent=${IMAGE_NAME}:${TAG}

echo "DaemonSet updated. Waiting for rollout to complete..."
kubectl -n ${NAMESPACE} rollout status daemonset/abproxy-agent

echo "Deployment completed!" 