#!/bin/bash

# Set variables
CLUSTER_NAME="abproxy-cluster"
REGION="nyc1"
NODE_SIZE="s-2vcpu-4gb"
NODE_COUNT=1

# Create DO Kubernetes cluster
echo "Creating DigitalOcean Kubernetes cluster..."
doctl kubernetes cluster create $CLUSTER_NAME \
  --region $REGION \
  --node-pool "name=default;size=$NODE_SIZE;count=$NODE_COUNT" \
  --wait

# Get kubeconfig
echo "Getting kubeconfig..."
doctl kubernetes cluster kubeconfig save $CLUSTER_NAME

# Create namespace
echo "Creating monitoring namespace..."
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -

# Deploy AutoMQ
echo "Deploying AutoMQ..."
kubectl apply -f deploy/automq.yaml

# Wait for AutoMQ to be ready
echo "Waiting for AutoMQ to be ready..."
kubectl rollout status -n monitoring statefulset/automq

# Deploy Quickwit
echo "Deploying Quickwit..."
kubectl apply -f deploy/quickwit.yaml

# Wait for Quickwit to be ready
echo "Waiting for Quickwit to be ready..."
kubectl rollout status -n monitoring statefulset/quickwit

# Deploy API server
echo "Deploying API server..."
kubectl apply -f cmd/api/api-deployment.yaml

# Wait for API server to be ready
echo "Waiting for API server to be ready..."
kubectl rollout status -n monitoring deployment/abproxy-api

echo "Kubernetes deployment completed successfully!" 