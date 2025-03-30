FROM ubuntu:22.04 as builder

# Install dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    linux-headers-generic \
    wget \
    git \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create symlinks for headers
RUN mkdir -p /usr/include/asm && \
    ln -s /usr/include/x86_64-linux-gnu/asm/types.h /usr/include/asm/types.h && \
    ln -s /usr/include/x86_64-linux-gnu/asm/byteorder.h /usr/include/asm/byteorder.h && \
    ln -s /usr/include/x86_64-linux-gnu/asm/bitsperlong.h /usr/include/asm/bitsperlong.h && \
    ln -s /usr/include/x86_64-linux-gnu/asm/posix_types.h /usr/include/asm/posix_types.h && \
    ln -s /usr/include/x86_64-linux-gnu/asm/posix_types_64.h /usr/include/asm/posix_types_64.h

# Install Go
RUN wget -q https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

WORKDIR /app
COPY . .

# Generate vmlinux.h
RUN mkdir -p pkg/tracer/bpf && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/tracer/bpf/vmlinux.h

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
    apt-get install -y libbpf0 linux-tools-common linux-tools-generic && \
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