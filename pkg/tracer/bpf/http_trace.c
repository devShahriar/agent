//+build ignore

// Force disable vDSO and version checks
#define CORE_DISABLE_VDSO_LOOKUP 1
#define HAVE_NO_VDSO 1

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stddef.h>  // For size_t

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

// Maximum size for our data buffer - must be power of 2
#define MAX_MSG_SIZE 256

// Export the typedef as a global declaration so bpf2go can find it
struct http_event_t {
    __u32 pid;          // Process ID
    __u32 tid;          // Thread ID
    __u64 timestamp;    // Event timestamp
    __u8 type;          // Event type (read/write)
    __u32 data_len;     // Length of the actual data
    __u32 conn_id;      // Connection ID to correlate request/response
    char data[MAX_MSG_SIZE]; // Actual HTTP data
} __attribute__((packed));

typedef struct http_event_t http_event_t;

// Define our own parameter access macros for x86_64
#define PT_REGS_PARAM1(x) ((x)->rdi)
#define PT_REGS_PARAM2(x) ((x)->rsi)
#define PT_REGS_PARAM3(x) ((x)->rdx)

// Event types
#define EVENT_TYPE_SSL_READ  1
#define EVENT_TYPE_SSL_WRITE 2

// Perf event map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, 4);  // Must be 0 or 4 for perf event array
    __uint(max_entries, 1024);
} events SEC(".maps");

// Function to handle SSL events - simplified version
static __always_inline
int handle_ssl_event(struct pt_regs *ctx, void *ssl_ctx, void *buf, unsigned int count, __u8 event_type) {
    // Quick bounds check
    if (!buf || count == 0 || count > MAX_MSG_SIZE) {
        return 0;
    }

    // Create event with minimal data
    http_event_t event = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF,
        .timestamp = bpf_ktime_get_ns(),
        .type = event_type,
        .data_len = count
    };
    
    // Set connection ID if available
    if (ssl_ctx) {
        event.conn_id = (__u32)(unsigned long)ssl_ctx;
    }
    
    // Read data into event with fixed size to prevent verifier issues
    if (bpf_probe_read_user(&event.data[0], MAX_MSG_SIZE, buf) == 0) {
        // Send event to userspace
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

// Simple SEC names for uprobe functions
SEC("uprobe/libssl.so.3:SSL_read")
int trace_ssl_read(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARAM1(ctx);
    void *buf = (void *)PT_REGS_PARAM2(ctx);
    unsigned int num = (unsigned int)PT_REGS_PARAM3(ctx);
    
    return handle_ssl_event(ctx, ssl, buf, num, EVENT_TYPE_SSL_READ);
}

SEC("uprobe/libssl.so.3:SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARAM1(ctx);
    void *buf = (void *)PT_REGS_PARAM2(ctx);
    unsigned int num = (unsigned int)PT_REGS_PARAM3(ctx);
    
    return handle_ssl_event(ctx, ssl, buf, num, EVENT_TYPE_SSL_WRITE);
}

// Explicitly set program version to avoid vDSO lookup
__u32 _version SEC("version") = 0xFFFFFFFE;

char LICENSE[] SEC("license") = "Dual BSD/GPL";
