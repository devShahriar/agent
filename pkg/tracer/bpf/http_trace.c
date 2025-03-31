//+build ignore

// Force disable vDSO and version checks
#define CORE_DISABLE_VDSO_LOOKUP 1
#define HAVE_NO_VDSO 1

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

// Define our own parameter access macros for x86_64
#define PT_REGS_PARAM1(x) ((x)->rdi)
#define PT_REGS_PARAM2(x) ((x)->rsi)
#define PT_REGS_PARAM3(x) ((x)->rdx)

// Maximum size for our data buffer - must be power of 2
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

// Add typedef for bpf2go to use
typedef struct http_event http_event_t;

// Perf event map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, 4);  // Must be 0 or 4 for perf event array
    __uint(max_entries, 1024);
} events SEC(".maps");

// Fixed-size read function that the verifier can analyze properly
static __always_inline int
safe_read_user(void *dst, const void *src, size_t size)
{
    // Fixed-size access that the verifier can analyze
    const int ret = bpf_probe_read_user(dst, MAX_MSG_SIZE, src);
    return ret;
}

// Function to handle SSL events
static __always_inline
int handle_ssl_event(struct pt_regs *ctx, void *ssl_ctx, void *buf, unsigned int count, __u8 event_type) {
    struct http_event event = {};
    
    // Get process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Set event metadata
    event.timestamp = bpf_ktime_get_ns();
    event.type = event_type;
    
    // Safety check for the connection ID
    if (ssl_ctx) {
        event.conn_id = (__u32)(unsigned long)ssl_ctx;
    } else {
        event.conn_id = 0;
    }
    
    // Safety check for buffer and count
    if (!buf || count == 0) {
        return 0;
    }
    
    // Clamp to fixed max size
    if (count > MAX_MSG_SIZE) {
        count = MAX_MSG_SIZE;
    }
    
    // Store actual data length
    event.data_len = count;
    
    // Use our safe read function with fixed size
    if (safe_read_user(event.data, buf, MAX_MSG_SIZE) == 0) {
        // Only send event on successful read
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

// Simple SEC names for uprobe functions
SEC("uprobe")
int trace_ssl_read(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARAM1(ctx);
    void *buf = (void *)PT_REGS_PARAM2(ctx);
    unsigned int num = (unsigned int)PT_REGS_PARAM3(ctx); // Explicitly use unsigned
    
    return handle_ssl_event(ctx, ssl, buf, num, EVENT_TYPE_SSL_READ);
}

SEC("uprobe")
int trace_ssl_write(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARAM1(ctx);
    void *buf = (void *)PT_REGS_PARAM2(ctx);
    unsigned int num = (unsigned int)PT_REGS_PARAM3(ctx); // Explicitly use unsigned
    
    return handle_ssl_event(ctx, ssl, buf, num, EVENT_TYPE_SSL_WRITE);
}

// Explicitly set program version to avoid vDSO lookup
// This is a special value that tells BPF to skip kernel version detection
__u32 _version SEC("version") = 0xFFFFFFFE;

char LICENSE[] SEC("license") = "Dual BSD/GPL";
