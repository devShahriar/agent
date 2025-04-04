#!/bin/bash
set -e

echo "Deploying Go HTTP test environment to Kubernetes..."

# Check if monitoring namespace exists, create if not
if ! kubectl get namespace monitoring &> /dev/null; then
  echo "Creating monitoring namespace..."
  kubectl create namespace monitoring
fi

# Apply the server deployment
echo "Deploying Go test server..."
kubectl apply -f k8s/go-test-server.yaml

# Wait for server to be ready
echo "Waiting for Go test server to be ready..."
kubectl -n monitoring wait --for=condition=available deployment/go-test-server --timeout=60s

# Apply the client deployment
echo "Deploying Go test client..."
kubectl apply -f k8s/go-test-client.yaml

echo "Test environment deployed successfully!"
echo ""
echo "To check the logs from the test server:"
echo "kubectl -n monitoring logs -f deployment/go-test-server"
echo ""
echo "To check the logs from the test client:"
echo "kubectl -n monitoring logs -f deployment/go-test-client"
echo ""
echo "To check if the ABProxy agent is capturing traffic:"
echo "kubectl -n monitoring logs -f daemonset/abproxy-agent | grep -i uniquetest123" 