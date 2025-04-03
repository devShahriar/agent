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

// Event structure to pass data to userspace
typedef struct {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u8 type;
    __u32 data_len;
    __u32 conn_id;
    char data[MAX_MSG_SIZE];
} __attribute__((packed)) http_event_t;

// Map to store events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Event types
#define EVENT_TYPE_SSL_READ  1
#define EVENT_TYPE_SSL_WRITE 2

// Helper function to get function parameters
static __always_inline void *get_param1(struct pt_regs *ctx) {
    return (void *)ctx->rdi;
}

static __always_inline void *get_param2(struct pt_regs *ctx) {
    return (void *)ctx->rsi;
}

static __always_inline unsigned int get_param3(struct pt_regs *ctx) {
    return (unsigned int)ctx->rdx;
}

// Helper function to safely read user data
static __always_inline int safe_read_user(void *dst, unsigned int size, const void *src) {
    // Ensure size is within bounds using bitwise AND
    size &= (MAX_MSG_SIZE - 1);
    if (size == 0) {
        return -1;
    }
    return bpf_probe_read_user(dst, size, src);
}

// Trace SSL_read
SEC("uprobe/libssl.so.3:SSL_read")
int trace_ssl_read(struct pt_regs *ctx) {
    http_event_t event = {};
    void *buf = get_param2(ctx);
    unsigned int len = get_param3(ctx);

    // Get process and thread IDs
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SSL_READ;
    event.conn_id = (__u32)(unsigned long)get_param1(ctx);

    // Log debug information
    bpf_printk("SSL_read: pid=%d", event.pid);
    bpf_printk("SSL_read: tid=%d", event.tid);
    bpf_printk("SSL_read: len=%d", len);
    bpf_printk("SSL_read: buf=%p", buf);

    // Copy data if buffer is valid
    if (buf != NULL) {
        event.data_len = len;
        if (safe_read_user(event.data, len, buf) < 0) {
            event.data_len = 0;
            bpf_printk("SSL_read: failed to read data");
        } else {
            bpf_printk("SSL_read: read %d bytes", event.data_len);
        }
    } else {
        bpf_printk("SSL_read: invalid buffer");
    }

    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Trace SSL_write
SEC("uprobe/libssl.so.3:SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    http_event_t event = {};
    void *buf = get_param2(ctx);
    unsigned int len = get_param3(ctx);

    // Get process and thread IDs
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SSL_WRITE;
    event.conn_id = (__u32)(unsigned long)get_param1(ctx);

    // Log debug information
    bpf_printk("SSL_write: pid=%d", event.pid);
    bpf_printk("SSL_write: tid=%d", event.tid);
    bpf_printk("SSL_write: len=%d", len);
    bpf_printk("SSL_write: buf=%p", buf);

    // Copy data if buffer is valid
    if (buf != NULL) {
        event.data_len = len;
        if (safe_read_user(event.data, len, buf) < 0) {
            event.data_len = 0;
            bpf_printk("SSL_write: failed to read data");
        } else {
            bpf_printk("SSL_write: read %d bytes", event.data_len);
        }
    } else {
        bpf_printk("SSL_write: invalid buffer");
    }

    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// Explicitly set program version to avoid vDSO lookup
__u32 _version SEC("version") = 0xFFFFFFFE;

char _license[] SEC("license") = "GPL";
