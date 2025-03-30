FROM ubuntu:22.04 as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    golang \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Download pre-generated vmlinux.h (for kernel 5.15)
RUN mkdir -p pkg/tracer/bpf && \
    wget -O pkg/tracer/bpf/vmlinux.h https://raw.githubusercontent.com/aquasecurity/tracee/main/pkg/ebpf/c/vmlinux.h

# Build agent
RUN cd pkg/tracer && go generate
RUN go build -o abproxy-agent ./cmd/agent

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libbpf0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/abproxy-agent /usr/local/bin/

# Set capabilities for BPF operations
RUN setcap cap_sys_admin,cap_bpf,cap_perfmon+eip /usr/local/bin/abproxy-agent

ENTRYPOINT ["/usr/local/bin/abproxy-agent"] 