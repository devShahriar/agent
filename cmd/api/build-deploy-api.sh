#!/bin/bash

# Build the API server Docker image
docker build -t devshahriar/abproxy-api:v1.0.0 -f Dockerfile .

# Push the image to Docker Hub
docker push devshahriar/abproxy-api:v1.0.0

# Deploy to Kubernetes
kubectl apply -f api-deployment.yaml

# Wait for deployment to complete
kubectl rollout status -n monitoring deployment/abproxy-api

echo "API server deployment completed successfully!" 