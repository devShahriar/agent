#!/bin/bash
set -e

echo "Building and deploying ABProxy agent with Elasticsearch support..."

# Build the agent image
echo "Building Docker image..."
docker build -t devshahriar/abproxy-agent:v1.38.0-es .

# Push the image
echo "Pushing Docker image..."
docker push devshahriar/abproxy-agent:v1.38.0-es

# Create the elasticsearch config map
echo "Creating Elasticsearch ConfigMap..."
kubectl create configmap abproxy-elasticsearch-config -n monitoring --from-file=config/elasticsearch.yaml --dry-run=client -o yaml | kubectl apply -f -

# Check if the agent is already deployed
if kubectl get daemonset -n monitoring abproxy-agent &> /dev/null; then
  echo "ABProxy agent already exists, updating..."
  
  # Update the image
  kubectl set image daemonset/abproxy-agent -n monitoring abproxy-agent=devshahriar/abproxy-agent:v1.38.0-es
  
  # Patch the DaemonSet to add the ConfigMap volume and volume mount if not already added
  if ! kubectl get daemonset abproxy-agent -n monitoring -o json | grep -q "elasticsearch-config"; then
    echo "Adding Elasticsearch configuration to agent..."
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
      }
    ]'
  fi
  
  # Add environment variable to use Elasticsearch storage
  if ! kubectl get daemonset abproxy-agent -n monitoring -o json | grep -q "STORAGE_TYPE"; then
    echo "Setting agent to use Elasticsearch storage..."
    kubectl patch daemonset abproxy-agent -n monitoring --type=json -p '[
      {
        "op": "add",
        "path": "/spec/template/spec/containers/0/env/-",
        "value": {
          "name": "STORAGE_TYPE",
          "value": "elasticsearch"
        }
      }
    ]'
  fi
else
  echo "ABProxy agent not found, creating new deployment..."
  # First make sure the monitoring namespace exists
  kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
  
  # Apply the daemonset with Elasticsearch configuration
  cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: abproxy-agent
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: abproxy-agent
  template:
    metadata:
      labels:
        app: abproxy-agent
    spec:
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      initContainers:
      - name: bpf-mount
        image: devshahriar/abproxy-agent:v1.38.0-es
        command: ["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: sys
          mountPath: /sys
        resources:
          limits:
            cpu: 100m
            memory: 50Mi
          requests:
            cpu: 10m
            memory: 10Mi
      containers:
      - name: abproxy-agent
        image: devshahriar/abproxy-agent:v1.38.0-es
        env:
        - name: DEBUG
          value: "true"
        - name: LOG_LEVEL
          value: "debug"
        - name: STORAGE_TYPE
          value: "elasticsearch"
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - SYS_RESOURCE
            - SYS_PTRACE
        volumeMounts:
        - name: sys
          mountPath: /sys
        - name: modules
          mountPath: /lib/modules
        - name: debug
          mountPath: /sys/kernel/debug
        - name: elasticsearch-config
          mountPath: /app/config/elasticsearch.yaml
          subPath: elasticsearch.yaml
        resources:
          limits:
            cpu: 500m
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 50Mi
      volumes:
      - name: sys
        hostPath:
          path: /sys
      - name: modules
        hostPath:
          path: /lib/modules
      - name: debug
        hostPath:
          path: /sys/kernel/debug
      - name: elasticsearch-config
        configMap:
          name: abproxy-elasticsearch-config
EOF
fi

echo "Deployment completed!"
echo ""
echo "To verify the agent is running:"
echo "kubectl get pods -n monitoring"
echo ""
echo "To check agent logs:"
echo "kubectl logs -n monitoring -l app=abproxy-agent --tail=50"
echo ""
echo "To test Elasticsearch integration:"
echo "./test-elasticsearch.sh" 