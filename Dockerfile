FROM ubuntu:22.04 as builder

# Install dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
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

# Set up BPF headers
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/x86_64-linux-gnu/bits /usr/include/bits && \
    ln -sf /usr/include/x86_64-linux-gnu/sys /usr/include/sys && \
    ln -sf /usr/include/x86_64-linux-gnu/linux /usr/include/linux && \
    ln -sf /usr/include/x86_64-linux-gnu/generated /usr/include/generated

# Initialize go module and install dependencies
RUN go mod init abproxy || true && \
    go mod tidy && \
    go install github.com/cilium/ebpf/cmd/bpf2go@v0.11.0

# Generate eBPF code with correct flags
RUN cd pkg/tracer && \
    CFLAGS="-I/usr/include/x86_64-linux-gnu" go generate

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