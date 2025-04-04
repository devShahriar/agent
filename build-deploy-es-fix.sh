#!/bin/bash
# Script to build and deploy ABProxy agent with Elasticsearch formatting fix

set -e

echo "Building new Docker image with Elasticsearch formatting fix..."
docker build -t devshahriar/abproxy-agent:v1.47.0 -f Dockerfile.k8 .

echo "Pushing new image to registry..."
docker push devshahriar/abproxy-agent:v1.47.0

echo "Updating DaemonSet to use new image..."
kubectl set image daemonset/abproxy-agent -n monitoring abproxy-agent=devshahriar/abproxy-agent:v1.47.0

echo "Waiting for rollout to complete..."
kubectl rollout status daemonset/abproxy-agent -n monitoring

echo "Deployment complete. The agent will now store formatted HTTP data in Elasticsearch." 