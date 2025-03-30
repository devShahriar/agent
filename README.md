# ABproxy HTTP Traffic Tracing Agent

An HTTP traffic tracing agent using eBPF technology, designed to run in Kubernetes environments.

## Overview

This project provides a transparent HTTP traffic tracing capability using eBPF uprobes attached to SSL/TLS library functions. It captures HTTP traffic without requiring application modifications.

## Features

- Intercepts SSL/TLS traffic using eBPF uprobes
- Captures HTTP request and response data
- Provides process and timing information for each HTTP transaction
- Outputs events in structured JSON format

## Development Environment

### Prerequisites

- Docker and Docker Compose
- VS Code with Remote Containers extension or JetBrains GoLand with remote development capability

### Option 1: Using Docker Compose Directly

```bash
# Build and start the development environment
docker-compose up -d --build

# Access the container shell
docker exec -it agent-dev-1 /bin/bash

# Run the agent
cd /app
./abproxy-agent
```

### Option 2: Using DevContainer (Recommended)

This project includes a DevContainer configuration that provides a complete eBPF development environment, which works even on macOS with Apple Silicon.

1. Open the project in VS Code
2. When prompted, click "Reopen in Container"
3. VS Code will build and start the development container

Alternatively, with GoLand:

1. Open the project in GoLand
2. Click on the container icon when opening up `.devcontainer/devcontainer.json`
3. Click on "Create Dev Container and Mount Sources..."

### Building eBPF Code

The eBPF code is written in C and located in `pkg/tracer/bpf/http_trace.c`. To generate the Go bindings for this code:

```bash
# Generate eBPF code bindings
go generate ./pkg/tracer
```

### Running the Agent

```bash
# Run the agent (requires root privileges)
sudo go run cmd/agent/main.go
```

## Project Structure

- `cmd/agent/`: Main application entry point
- `pkg/tracer/`: Core tracing functionality
  - `bpf/`: eBPF C code
    - `headers/`: BPF header files
    - `http_trace.c`: Main eBPF program
  - `tracer.go`: Go code interfacing with eBPF

## License

MIT

## Storage Options

ABproxy offers flexible storage options for the captured HTTP traffic:

### File Storage

The default storage option saves HTTP transactions as JSON or raw text files. This is useful for local development and debugging.

```bash
# Run with file storage (default)
./abproxy-agent --storage=file --file-dir=/path/to/data --file-prefix=http-traffic

# Options:
# --file-dir: Directory to store files (default: ./data)
# --file-prefix: Prefix for filenames (default: http-traffic)
# --file-raw: Use raw text format instead of JSON (default: false)
# --save-events: Save individual events in addition to transactions (default: false)
```

### Elasticsearch Storage

For production deployments, Elasticsearch storage provides powerful search and visualization capabilities. Kibana is included for easy data exploration.

```bash
# Run with Elasticsearch storage
./abproxy-agent --storage=elasticsearch --es-url=http://elasticsearch:9200

# Options:
# --es-url: Elasticsearch URL (default: http://elasticsearch:9200)
# --es-auth: Basic auth in format "username:password" (default: none)
# --es-prefix: Index prefix (default: abproxy)
# --save-events: Save individual events in addition to transactions (default: false)
```

### Kubernetes Deployment with Elasticsearch

To deploy the agent with Elasticsearch in Kubernetes:

```bash
# Deploy Elasticsearch and Kibana
kubectl apply -f deploy/kubernetes/elasticsearch.yaml

# Deploy the agent with Elasticsearch storage
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

Access Kibana at http://[CLUSTER-IP]:5601 to view and analyze captured HTTP traffic.

## Deployment

### Quick Deployment with Test Services

For a complete deployment including test services that generate HTTP traffic:

```bash
# Clone the repository
git clone https://github.com/yourusername/abproxy.git
cd abproxy

# Deploy everything (Elasticsearch, Kibana, agent, and test services)
cd deploy/kubernetes
./deploy-all.sh
```

This will:

1. Deploy Elasticsearch and Kibana in the `monitoring` namespace
2. Deploy the ABProxy agent as a DaemonSet
3. Deploy dummy HTTP services that generate traffic for testing
4. Provide instructions for accessing Kibana to view the captured traffic

### Manual Deployment

#### Kubernetes

```bash
# Deploy Elasticsearch and Kibana first
kubectl apply -f deploy/kubernetes/elasticsearch.yaml

# Deploy the agent
kubectl apply -f deploy/kubernetes/daemonset.yaml

# Optionally deploy test services
kubectl apply -f deploy/kubernetes/dummy-service.yaml
```

#### Docker Compose (Development)

```bash
docker-compose up -d --build
```

### Accessing the Dashboard

To access Kibana for viewing HTTP traffic:

```bash
kubectl port-forward -n monitoring svc/kibana 5601:5601
```

Then open http://localhost:5601 in your browser.

1. Go to Stack Management > Index Patterns
2. Create index pattern "abproxy-\*"
3. Go to Discover to see the captured HTTP traffic
