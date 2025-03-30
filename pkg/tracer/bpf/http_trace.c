//+build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum size for our data buffer
#define MAX_MSG_SIZE 256

// Event types
#define EVENT_TYPE_SSL_READ  1
#define EVENT_TYPE_SSL_WRITE 2

// Event structure
struct http_event {
    __u32 pid;          // Process ID
    __u32 tid;          // Thread ID
    __u64 timestamp;    // Event timestamp
    __u8 type;          // Event type (read/write)
    __u32 data_len;     // Length of the actual data
    __u32 conn_id;      // Connection ID to correlate request/response
    char data[MAX_MSG_SIZE]; // Actual HTTP data
} __attribute__((packed));

// Perf event map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Function to handle SSL events
static __always_inline
int handle_ssl_event(struct pt_regs *ctx, void *ssl_ctx, void *buf, __u32 count, __u8 event_type) {
    struct http_event event = {};
    
    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    
    // Set event metadata
    event.timestamp = bpf_ktime_get_ns();
    event.type = event_type;
    event.conn_id = (__u32)(unsigned long)ssl_ctx;
    
    // Copy data with size limit
    __u32 read_len = count > MAX_MSG_SIZE ? MAX_MSG_SIZE : count;
    event.data_len = read_len;
    
    // Try to read the data
    if (bpf_probe_read_user(event.data, read_len, buf) == 0) {
        // Send event to userspace
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

SEC("uprobe/SSL_read")
int trace_ssl_read(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    __u32 num = (__u32)PT_REGS_PARM3(ctx);
    
    return handle_ssl_event(ctx, ssl, buf, num, EVENT_TYPE_SSL_READ);
}

SEC("uprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    __u32 num = (__u32)PT_REGS_PARM3(ctx);
    
    return handle_ssl_event(ctx, ssl, buf, num, EVENT_TYPE_SSL_WRITE);
}

// Version information to avoid vDSO lookup
volatile const unsigned long bpf_prog_version __attribute__((section("version"))) = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";
