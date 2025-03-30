//+build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Simple pt_regs structure for accessing function parameters
struct pt_regs {
    unsigned long regs[8];  // x86_64 has 8 general purpose registers we care about
};

// Parameter access macros for x86_64
#define PT_REGS_PARM1(x) ((x)->regs[0])  // First parameter in rdi
#define PT_REGS_PARM2(x) ((x)->regs[1])  // Second parameter in rsi
#define PT_REGS_PARM3(x) ((x)->regs[2])  // Third parameter in rdx

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
    __uint(max_entries, 1024);
} events SEC(".maps");

// Attach to SSL_read function
SEC("uprobe/SSL_read")
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
    
    // Copy data with safe size
    bpf_probe_read_user(event.data, read_len, buf);
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Attach to SSL_write function
SEC("uprobe/SSL_write")
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
