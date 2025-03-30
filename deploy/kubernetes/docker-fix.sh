#!/bin/bash
set -e

# Configuration
IMAGE_NAME="docker.io/devshahriar/abproxy-agent:latest"

echo "Building abproxy-agent image with a stub tracer..."

# Create a clean build directory
rm -rf build_linux
mkdir -p build_linux
cp -r $(ls -A | grep -v "build_linux") build_linux/

# Create a stub tracer.go that doesn't use BPF at all
cat > build_linux/pkg/tracer/tracer.go << 'EOG'
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

// Tracer manages the event collection
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
		logger.Info("Created stub tracer (no eBPF functionality)")
	}

	return t, nil
}

// Start begins tracing HTTP traffic
func (t *Tracer) Start() error {
	if t.logger != nil {
		t.logger.Info("Starting stub tracer (no actual tracing will occur)")
	}
	return nil
}

// Stop stops tracing HTTP traffic
func (t *Tracer) Stop() error {
	close(t.stopChan)
	return nil
}

// Close cleans up resources
func (t *Tracer) Close() error {
	return nil
}
EOG

# Create a simplified Dockerfile 
cat > build_linux/Dockerfile << 'EOD'
FROM golang:1.21 as builder

WORKDIR /app

# Copy source code
COPY . .

# Build the agent
RUN go mod init abproxy || true && \
    go mod edit -go=1.21 && \
    go get github.com/sirupsen/logrus@v1.9.3 && \
    go mod tidy && \
    go build -o abproxy-agent ./cmd/agent

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
EOD

# Build the Docker image
echo "Building Docker image..."
cd build_linux
docker build -t $IMAGE_NAME .
cd ..

# Clean up
rm -rf build_linux

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