#!/bin/bash

# Build the agent
echo "Building the agent..."
docker build -t devshahriar/abproxy-agent:v1.47.0 -f Dockerfile.k8 .

# Push to Docker Hub
echo "Pushing to Docker Hub..."
docker push devshahriar/abproxy-agent:v1.47.0

# Update the image in the DaemonSet
echo "Updating the DaemonSet..."
kubectl set image -n monitoring daemonset/abproxy-agent abproxy-agent=devshahriar/abproxy-agent:v1.47.0

# Wait for the rollout to complete
echo "Waiting for rollout to complete..."
kubectl rollout status -n monitoring daemonset/abproxy-agent

echo "Done! Transaction support should now be working." 