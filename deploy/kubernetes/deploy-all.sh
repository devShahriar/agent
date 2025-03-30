#!/bin/bash

# Create monitoring namespace if it doesn't exist
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -

# Deploy Elasticsearch and Kibana
echo "Deploying Elasticsearch and Kibana..."
kubectl apply -f elasticsearch.yaml

# Wait for Elasticsearch to be ready
echo "Waiting for Elasticsearch to be ready..."
kubectl wait --namespace=monitoring --for=condition=ready pod -l app=elasticsearch --timeout=300s

# Deploy the agent DaemonSet
echo "Deploying ABProxy agent..."
kubectl apply -f daemonset.yaml

# Deploy dummy services for testing
echo "Deploying dummy HTTP services for testing..."
kubectl apply -f dummy-service.yaml

echo "Deployment complete!"
echo ""
echo "To access Kibana, run: kubectl port-forward -n monitoring svc/kibana 5601:5601"
echo "Then open http://localhost:5601 in your browser"
echo ""
echo "To watch traffic between dummy services:"
echo "1. Open Kibana"
echo "2. Go to Stack Management > Index Patterns"
echo "3. Create index pattern 'abproxy-*'"
echo "4. Go to Discover to see the captured HTTP traffic" 