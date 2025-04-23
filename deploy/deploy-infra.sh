#!/bin/bash

# Create namespace if it doesn't exist
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -

# Deploy AutoMQ
echo "Deploying AutoMQ..."
kubectl apply -f automq.yaml

# Wait for AutoMQ to be ready
echo "Waiting for AutoMQ to be ready..."
kubectl rollout status -n monitoring statefulset/automq

# Deploy Quickwit
echo "Deploying Quickwit..."
kubectl apply -f quickwit.yaml

# Wait for Quickwit to be ready
echo "Waiting for Quickwit to be ready..."
kubectl rollout status -n monitoring statefulset/quickwit

echo "Infrastructure deployment completed successfully!" 