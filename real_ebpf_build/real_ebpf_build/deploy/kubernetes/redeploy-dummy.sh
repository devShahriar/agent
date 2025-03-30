#!/bin/bash
set -e

echo "Redeploying dummy test services..."

# Delete existing deployments and services
kubectl delete deployment dummy-http-service dummy-client
kubectl delete service dummy-http-service dummy-client

# Apply the updated configuration
kubectl apply -f deploy/kubernetes/dummy-service.yaml

echo "Waiting for services to be ready..."
kubectl wait --for=condition=ready pod -l app=dummy-http --timeout=60s
kubectl wait --for=condition=ready pod -l app=dummy-client --timeout=60s

echo "Dummy services redeployed successfully!"
echo ""
echo "To test manually, run:"
echo "kubectl exec -it \$(kubectl get pod -l app=dummy-client -o jsonpath='{.items[0].metadata.name}') -- sh"
echo "Then inside the container, run: curl -v http://dummy-http-service/get" 