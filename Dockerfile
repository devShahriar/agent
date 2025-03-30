FROM ubuntu:22.04 as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    golang \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Generate vmlinux.h
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/tracer/bpf/vmlinux.h

# Build agent
RUN cd pkg/tracer && go generate
RUN go build -o abproxy-agent ./cmd/agent

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    linux-tools-common \
    linux-tools-generic \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/abproxy-agent /usr/local/bin/

# Set capabilities for BPF operations
RUN setcap cap_sys_admin,cap_bpf,cap_perfmon+eip /usr/local/bin/abproxy-agent

ENTRYPOINT ["/usr/local/bin/abproxy-agent"] 