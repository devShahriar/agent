#!/bin/bash
set -e

# Configuration
IMAGE_NAME="docker.io/devshahriar/abproxy-agent:latest"

echo "Building abproxy-agent image with stub eBPF implementation..."

# Create a stub tracer implementation
mkdir -p stub_build/pkg/tracer/bpf
cat > stub_build/pkg/tracer/tracer.go << 'EOF'
package tracer

import (
	"github.com/sirupsen/logrus"
)

// Event types
const (
	EventTypeSSLRead  = 1 // Response
	EventTypeSSLWrite = 2 // Request
)

// HTTPEvent represents a captured HTTP event
type HTTPEvent struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	Type      uint8
	DataLen   uint32
	ConnID    uint32 // Connection ID to correlate request/response
	Data      [256]byte

	// Parsed information (not part of the eBPF struct)
	ProcessName string
	Command     string
	Method      string
	URL         string
	StatusCode  int
	ContentType string
}

// Clone returns a copy of the HTTPEvent
func (e *HTTPEvent) Clone() *HTTPEvent {
	clone := *e // Shallow copy
	return &clone
}

// Tracer manages the eBPF program and event collection
type Tracer struct {
	logger        *logrus.Logger
	eventCallback func(HTTPEvent)
	stopChan      chan struct{}
}

// NewTracer creates a new HTTP tracer
func NewTracer(logger *logrus.Logger, callback func(HTTPEvent)) (*Tracer, error) {
	t := &Tracer{
		logger:        logger,
		eventCallback: callback,
		stopChan:      make(chan struct{}),
	}
	
	if logger != nil {
		logger.Info("Created stub tracer implementation (for Kubernetes deployment)")
	}
	
	return t, nil
}

// Start begins tracing HTTP traffic
func (t *Tracer) Start() error {
	if t.logger != nil {
		t.logger.Info("Starting stub tracer (no actual eBPF tracing)")
	}
	return nil
}

// Stop stops tracing HTTP traffic
func (t *Tracer) Stop() error {
	if t.logger != nil {
		t.logger.Info("Stopping tracer")
	}
	close(t.stopChan)
	return nil
}

// Close cleans up resources
func (t *Tracer) Close() error {
	if t.logger != nil {
		t.logger.Info("Closing tracer")
	}
	return nil
}
EOF

# Copy the rest of the codebase
echo "Copying the rest of the codebase..."
rsync -a --exclude="pkg/tracer" ./ stub_build/

# Create a Dockerfile for the stub implementation
cat > stub_build/Dockerfile << 'EOF'
FROM golang:1.21 as builder

WORKDIR /app
COPY . .

# Initialize go module and install dependencies
RUN go mod init abproxy || true && \
    go mod edit -go=1.21 && \
    go get github.com/cilium/ebpf@v0.11.0 && \
    go get github.com/cilium/ebpf/link@v0.11.0 && \
    go get github.com/cilium/ebpf/perf@v0.11.0 && \
    go get github.com/sirupsen/logrus@v1.9.3 && \
    go get golang.org/x/sys@v0.15.0 && \
    go mod tidy

# Build the agent (no eBPF generation needed with stub)
RUN go build -o abproxy-agent ./cmd/agent

# Final stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/abproxy-agent .

ENTRYPOINT ["/app/abproxy-agent"]
EOF

# Build the Docker image
echo "Building Docker image..."
cd stub_build
docker build -t $IMAGE_NAME .
cd ..

# Clean up
rm -rf stub_build

echo "Image built successfully: $IMAGE_NAME"

# Ask for confirmation before pushing
read -p "Push image to $IMAGE_NAME? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Logging in to Docker Hub..."
    docker login
    
    echo "Pushing image to Docker Hub..."
    docker push $IMAGE_NAME
    
    echo "Image pushed successfully!"
    
    # Update daemonset file with the image
    sed -i.bak "s|image: .*|image: $IMAGE_NAME|g" deploy/kubernetes/daemonset.yaml
    echo "Updated deploy/kubernetes/daemonset.yaml with the image reference."
fi

echo "Done!" 