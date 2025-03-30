FROM ubuntu:22.04 as builder

# Install dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    linux-tools-generic \
    wget \
    git \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget -q https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

WORKDIR /app
COPY . .

# Download pre-generated vmlinux.h and set up BPF headers
RUN mkdir -p pkg/tracer/bpf && \
    wget -O pkg/tracer/bpf/vmlinux.h https://raw.githubusercontent.com/aquasecurity/tracee/main/pkg/ebpf/c/vmlinux.h && \
    ln -s /usr/include/bpf /usr/include/linux/bpf

# Initialize go module and install dependencies
RUN go mod init abproxy || true && \
    go mod tidy && \
    go install github.com/cilium/ebpf/cmd/bpf2go@v0.11.0

# Generate eBPF code
RUN cd pkg/tracer && go generate

# Build the agent
RUN go build -o abproxy-agent ./cmd/agent

# Final stage
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