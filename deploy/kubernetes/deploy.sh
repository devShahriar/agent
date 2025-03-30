#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Build the Docker image
echo "Building Docker image..."
docker build -t abproxy-agent:latest "${ROOT_DIR}"

# Create the monitoring namespace if it doesn't exist
echo "Creating monitoring namespace if it doesn't exist..."
kubectl get namespace monitoring || kubectl create namespace monitoring

# Apply the Kubernetes manifests
echo "Applying Kubernetes manifests..."
kubectl apply -f "${SCRIPT_DIR}/daemonset.yaml"

echo "Deployment completed successfully!"
echo "To view logs from the agent, run:"
echo "  kubectl logs -n monitoring -l app=abproxy-agent -f" 