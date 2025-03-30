FROM ubuntu:22.04 as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    pkg-config \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.21
RUN wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

WORKDIR /app

# Copy source code
COPY . .

# Set up BPF headers
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/x86_64-linux-gnu/bits /usr/include/bits && \
    ln -sf /usr/include/x86_64-linux-gnu/sys /usr/include/sys && \
    ln -sf /usr/include/x86_64-linux-gnu/linux /usr/include/linux

# Download pre-generated vmlinux.h (for kernel 5.15)
RUN mkdir -p pkg/tracer/bpf && \
    wget -O pkg/tracer/bpf/vmlinux.h https://raw.githubusercontent.com/aquasecurity/tracee/main/pkg/ebpf/c/vmlinux.h

# Initialize go module and install dependencies
RUN go mod download
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Generate BPF code and build agent
RUN cd pkg/tracer && \
    GOOS=linux GOARCH=amd64 go generate && \
    go build -o ../../abproxy-agent ./cmd/agent

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libbpf0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/abproxy-agent /usr/local/bin/

# Set capabilities for BPF operations
RUN setcap cap_sys_admin,cap_bpf,cap_perfmon+eip /usr/local/bin/abproxy-agent

ENTRYPOINT ["/usr/local/bin/abproxy-agent"] 