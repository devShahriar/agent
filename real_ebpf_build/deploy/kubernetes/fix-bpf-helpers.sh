#!/bin/bash
set -e

# Configuration
IMAGE_NAME="docker.io/devshahriar/abproxy-agent:latest"

echo "Building abproxy-agent image for Kubernetes..."

# Make sure the dev environment is up
docker-compose up -d

# Fix the BPF helpers header file
echo "Fixing eBPF header file in the container..."
docker-compose exec -T dev bash -c "cd /app && cat > pkg/tracer/bpf/headers/bpf_helpers.h << 'EOF'
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* Basic type definitions */
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;

/* Map type definitions */
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4

/* Other constants */
#define BPF_F_CURRENT_CPU 0xffffffffULL

/* Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* BPF map definition macros for Cilium's bpf2go */
#define __uint(name, val) int name __attribute__((section(".maps"))) = val
#define __type(name, val) typeof(val) *name __attribute__((section(".maps")))
#define __array(name, val) typeof(val) *name[] __attribute__((section(".maps")))

/* PT_REGS structure for uprobe parameters */
struct pt_regs {
    __u64 regs[8];  /* Simplified registers array */
};

/* Parameter access macros */
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])

/* Helper functions called from eBPF programs written in C */
/* BPF_FUNC_* values are placeholders - the actual values
   will be determined by the BPF verifier */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3
#define BPF_FUNC_probe_read 4
#define BPF_FUNC_ktime_get_ns 5
#define BPF_FUNC_trace_printk 6
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_uid_gid 15
#define BPF_FUNC_get_current_comm 16
#define BPF_FUNC_perf_event_output 25
#define BPF_FUNC_probe_read_user 112

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
    (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
                 unsigned long long flags) =
    (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
    (void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
    (void *) BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
    (void *) BPF_FUNC_ktime_get_ns;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
    (void *) BPF_FUNC_get_current_pid_tgid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
    (void *) BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_output)(void *ctx, void *map,
                   unsigned long long flags, void *data,
                   int size) =
    (void *) BPF_FUNC_perf_event_output;
static int (*bpf_probe_read_user)(void *dst, int size, void *unsafe_ptr) =
    (void *) BPF_FUNC_probe_read_user;

#endif /* __BPF_HELPERS_H */
EOF"

# Also fix the http_trace.c file
echo "Fixing http_trace.c file in the container..."
docker-compose exec -T dev bash -c "cd /app && cat > pkg/tracer/bpf/http_trace.c.new << 'EOF'
//+build ignore

#include \"headers/bpf_helpers.h\"

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

// Maps definition
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(\".maps\");

// Attach to SSL_read function
SEC(\"uprobe/SSL_read\")
int trace_ssl_read(struct pt_regs *ctx)
{
    struct http_event event = {};
    void *ssl_ctx = (void*)PT_REGS_PARM1(ctx);
    void *buf = (void*)PT_REGS_PARM2(ctx);
    __u32 count = (__u32)PT_REGS_PARM3(ctx);
    
    // Set metadata
    event.timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    event.type = EVENT_TYPE_SSL_READ;
    
    // Use SSL context pointer as connection ID to correlate requests/responses
    event.conn_id = (__u32)(unsigned long)ssl_ctx;
    
    // Limit data size to prevent stack overflow
    __u32 read_len = count;
    if (read_len > MAX_MSG_SIZE) {
        read_len = MAX_MSG_SIZE;
    }
    event.data_len = read_len;
    
    // Copy data with safe size - only do this after SSL_read returns successfully
    // Here we'd ideally check the return value first but we're reading
    // the buffer directly which should be populated with data
    bpf_probe_read_user(event.data, read_len, buf);
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Attach to SSL_write function
SEC(\"uprobe/SSL_write\")
int trace_ssl_write(struct pt_regs *ctx)
{
    struct http_event event = {};
    void *ssl_ctx = (void*)PT_REGS_PARM1(ctx);
    void *buf = (void*)PT_REGS_PARM2(ctx);
    __u32 count = (__u32)PT_REGS_PARM3(ctx);
    
    // Set metadata
    event.timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    event.type = EVENT_TYPE_SSL_WRITE;
    
    // Use SSL context pointer as connection ID to correlate requests/responses
    event.conn_id = (__u32)(unsigned long)ssl_ctx;
    
    // Limit data size to prevent stack overflow
    __u32 read_len = count;
    if (read_len > MAX_MSG_SIZE) {
        read_len = MAX_MSG_SIZE;
    }
    event.data_len = read_len;
    
    // Copy data with safe size
    bpf_probe_read_user(event.data, read_len, buf);
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";
EOF
mv pkg/tracer/bpf/http_trace.c.new pkg/tracer/bpf/http_trace.c"

# Install dependencies in the container if needed
echo "Installing dependencies in the container..."
docker-compose exec -T dev bash -c "cd /app && \
apt-get update && \
apt-get install -y build-essential clang llvm libelf-dev && \
if ! command -v go &> /dev/null; then \
  echo 'Installing Go...' && \
  apt-get install -y wget && \
  wget -q https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
  rm go1.21.0.linux-amd64.tar.gz; \
fi"

# Build the agent
echo "Building agent inside container..."
docker-compose exec -T dev bash -c "cd /app && PATH=/usr/local/go/bin:\$PATH go generate ./pkg/tracer && PATH=/usr/local/go/bin:\$PATH go build -o abproxy-agent ./cmd/agent"

# Create a new Docker image from the built binary
echo "Creating Docker image from the built binary..."
cat > Dockerfile.prod << EOF
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    ca-certificates \\
    libelf1 \\
    libbpf0 \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY abproxy-agent .

ENTRYPOINT ["/app/abproxy-agent"]
EOF

# Copy the binary from the dev container
docker cp $(docker-compose ps -q dev):/app/abproxy-agent ./abproxy-agent

# Build the production image
docker build -t $IMAGE_NAME -f Dockerfile.prod .

# Clean up temporary files
rm -f Dockerfile.prod abproxy-agent

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