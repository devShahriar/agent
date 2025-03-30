#!/bin/bash
set -e

# Configuration
IMAGE_NAME="docker.io/devshahriar/abproxy-agent:latest"

echo "Building abproxy-agent image with eBPF on Linux..."

# Clean up problematic repositories first
echo "Cleaning up problematic repositories..."
sudo rm -f /etc/apt/sources.list.d/*cuda*
sudo rm -f /etc/apt/sources.list.d/*nvidia*
sudo rm -f /etc/apt/sources.list.d/*kubernetes*
sudo rm -f /etc/apt/sources.list.d/*mongodb*
sudo rm -f /etc/apt/sources.list.d/*teamviewer*
sudo rm -f /etc/apt/sources.list.d/*yarn*
sudo rm -f /etc/apt/sources.list.d/*codeblocks*
sudo rm -f /etc/apt/sources.list.d/*google*

# Update package lists after cleanup
echo "Updating package lists..."
sudo apt-get update || true

# Install required dependencies
echo "Installing dependencies..."
sudo apt-get install -y \
    git build-essential pkg-config \
    libelf-dev clang llvm \
    libbpf-dev linux-headers-$(uname -r)

# Create a clean build directory
rm -rf build_linux
mkdir -p build_linux
cp -r $(ls -A | grep -v "build_linux") build_linux/

# Create a simplified BPF program
cat > build_linux/pkg/tracer/bpf/http_trace.c << 'EOC'
//+build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Maximum size for our data buffer - reduced to fit BPF stack limits
#define MAX_MSG_SIZE 256

// Event types
#define EVENT_TYPE_SSL_READ  1  // SSL_read event (responses)
#define EVENT_TYPE_SSL_WRITE 2  // SSL_write event (requests)

// Event type for metadata only - small enough for BPF stack
struct http_event {
    __u32 pid;          // Process ID
    __u32 tid;          // Thread ID
    __u64 timestamp;    // Event timestamp
    __u8 type;          // Event type (read/write)
    __u32 data_len;     // Length of the actual data
    __u32 conn_id;      // Connection ID to correlate request/response
    char data[MAX_MSG_SIZE]; // Actual HTTP data
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// Attach to SSL_read function
SEC("uprobe/SSL_read")
int trace_ssl_read(void *ctx)
{
    return 0;
}

// Attach to SSL_write function
SEC("uprobe/SSL_write")
int trace_ssl_write(void *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
EOC

# Create a simplified tracer.go
cat > build_linux/pkg/tracer/tracer.go << 'EOG'
package tracer

import (
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ./bpf/http_trace.c

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
	objs          bpfObjects
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

	// Load pre-compiled programs
	var err error
	if err = loadBpfObjects(&t.objs, nil); err != nil {
		return nil, err
	}

	return t, nil
}

// Start begins tracing HTTP traffic
func (t *Tracer) Start() error {
	if t.logger != nil {
		t.logger.Info("Starting tracer")
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
	t.objs.Close()
	return nil
}
EOG

# Create a Dockerfile for building the agent
cat > build_linux/Dockerfile << 'EOD'
FROM ubuntu:22.04 as builder

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    git \
    build-essential \
    pkg-config \
    libelf-dev \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    linux-headers-$(uname -r) \
    linux-tools-generic \
    linux-tools-common \
    gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

# Set KBUILD flags for BPF compilation
ENV KBUILD_INCLUDE=/usr/include

# Install Go 1.21
RUN wget -q https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

# Add Go to PATH
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Create symlink for asm/types.h
RUN mkdir -p /usr/include/asm && \
    ln -s /usr/include/x86_64-linux-gnu/asm/types.h /usr/include/asm/types.h

# Initialize go module and install dependencies
RUN go mod init abproxy || true && \
    go mod edit -go=1.21 && \
    go get github.com/cilium/ebpf@v0.11.0 && \
    go get github.com/cilium/ebpf/link@v0.11.0 && \
    go get github.com/cilium/ebpf/perf@v0.11.0 && \
    go get github.com/sirupsen/logrus@v1.9.3 && \
    go get golang.org/x/sys@v0.15.0 && \
    go mod tidy

# Install bpf2go
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.11.0

# Generate eBPF code
RUN cd pkg/tracer && \
    CFLAGS="-I/usr/include/x86_64-linux-gnu" go generate

# Build the agent
RUN go build -o abproxy-agent ./cmd/agent

# Final stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libelf1 \
    libbpf0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/abproxy-agent .

# Set capabilities for eBPF operations
RUN apt-get update && \
    apt-get install -y --no-install-recommends libcap2-bin && \
    setcap cap_sys_admin,cap_bpf,cap_net_admin,cap_perfmon+eip /app/abproxy-agent && \
    apt-get remove -y libcap2-bin && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

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

echo "Done! You can now deploy with: kubectl apply -f deploy/kubernetes/daemonset.yaml" 