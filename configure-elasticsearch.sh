#!/bin/bash
set -e

echo "Configuring ABProxy agent to use Elasticsearch..."

# Set config file path
CONFIG_DIR="./config"
ES_YAML="$CONFIG_DIR/elasticsearch.yaml"

# Check if config directory exists
if [ ! -d "$CONFIG_DIR" ]; then
  mkdir -p "$CONFIG_DIR"
  echo "Created config directory"
fi

# Create ConfigMap from the elasticsearch.yaml file
echo "Creating ConfigMap from elasticsearch.yaml..."
kubectl create configmap abproxy-elasticsearch-config -n monitoring --from-file=$ES_YAML --dry-run=client -o yaml | kubectl apply -f -

# Check if the agent is already deployed
if kubectl get daemonset -n monitoring abproxy-agent &> /dev/null; then
  echo "Updating existing ABProxy agent DaemonSet to use Elasticsearch..."
  
  # Patch the DaemonSet to add the ConfigMap volume and volume mount
  kubectl patch daemonset abproxy-agent -n monitoring --type=json -p '[
    {
      "op": "add", 
      "path": "/spec/template/spec/volumes/-", 
      "value": {
        "name": "elasticsearch-config",
        "configMap": {
          "name": "abproxy-elasticsearch-config"
        }
      }
    },
    {
      "op": "add", 
      "path": "/spec/template/spec/containers/0/volumeMounts/-", 
      "value": {
        "name": "elasticsearch-config",
        "mountPath": "/app/config/elasticsearch.yaml",
        "subPath": "elasticsearch.yaml"
      }
    },
    {
      "op": "add",
      "path": "/spec/template/spec/containers/0/env/-",
      "value": {
        "name": "STORAGE_TYPE",
        "value": "elasticsearch"
      }
    }
  ]'
else
  echo "ABProxy agent DaemonSet not found. Please deploy the agent first."
  exit 1
fi

echo "Configuration complete. The agent will now store HTTP transactions in Elasticsearch."
echo ""
echo "To test the integration:"
echo "1. Run: ./test-elasticsearch.sh"
echo "2. Check Kibana at http://kibana-service.monitoring.svc.cluster.local:5601"
echo "3. Create an index pattern 'abproxy-http-transactions-*'"
echo "4. You should see HTTP transactions with the 'uniquetest123' header." 