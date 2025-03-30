#!/bin/bash
set -e

echo "Building abproxy-agent with eBPF..."

# Install essential dependencies only
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    libbpf-dev \
    linux-headers-$(uname -r)

# Build Docker image with eBPF capabilities
docker build -t devshahriar/abproxy-agent:latest -f - . << 'EOF'
FROM ubuntu:22.04 as builder

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    clang \
    libbpf-dev \
    wget \
    git

# Install Go
RUN wget -q https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /app
COPY . .

# Build the agent
RUN go mod init abproxy || true && \
    go mod tidy && \
    go install github.com/cilium/ebpf/cmd/bpf2go@latest && \
    cd pkg/tracer && go generate && cd ../.. && \
    go build -o abproxy-agent ./cmd/agent

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y libbpf0 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/abproxy-agent /usr/local/bin/

# Add eBPF capabilities
RUN apt-get update && \
    apt-get install -y libcap2-bin && \
    setcap cap_bpf,cap_net_admin,cap_perfmon+eip /usr/local/bin/abproxy-agent && \
    apt-get remove -y libcap2-bin && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/abproxy-agent"]
EOF

echo "Build complete! To push to Docker Hub:"
echo "docker push devshahriar/abproxy-agent:latest"
echo
echo "To deploy to Kubernetes:"
echo "kubectl apply -f deploy/kubernetes/daemonset.yaml" 