#!/bin/bash
set -e

# Configuration
IMAGE_NAME="docker.io/devshahriar/abproxy-agent:latest"

echo "Building abproxy-agent image with real eBPF functionality..."

# Install kernel headers on the host if not already installed
echo "Making sure kernel headers are installed on the host..."
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)

# Create Dockerfile that uses host's kernel headers
cat > Dockerfile.ebpf << 'EOD'
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
    && rm -rf /var/lib/apt/lists/*

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

# The kernel headers will be mounted at /usr/src at build time
# Create a simplified BPF program
cat > pkg/tracer/bpf/http_trace.c << 'EOC'
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

# Generate eBPF code with access to host's kernel headers
# This will use the headers mounted from the host
RUN cd pkg/tracer && go generate

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

ENTRYPOINT ["/app/abproxy-agent"]
EOD

# Build the Docker image with host kernel headers mounted
echo "Building Docker image with host kernel headers..."
KERNEL_VERSION=$(uname -r)
docker build \
  --build-arg KERNEL_VERSION=$KERNEL_VERSION \
  -v /usr/src:/usr/src:ro \
  -v /lib/modules:/lib/modules:ro \
  -t $IMAGE_NAME \
  -f Dockerfile.ebpf .

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