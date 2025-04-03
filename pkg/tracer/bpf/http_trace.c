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

// Process info structure
struct process_info {
    __u32 pid;
    __u32 ppid;
    char comm[16];
} __attribute__((packed));

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
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps") = {};

// Map to store connection state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_state SEC(".maps") = {};

// Map to store process info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct process_info));
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_info SEC(".maps") = {};

// Event types
#define EVENT_TYPE_SSL_READ  1
#define EVENT_TYPE_SSL_WRITE 2

// Socket event types
#define EVENT_TYPE_SOCKET_READ  3
#define EVENT_TYPE_SOCKET_WRITE 4

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

// Helper function to check if data looks like HTTP
static __always_inline int is_http_data(const char *data, size_t len) {
    if (len < 3) {
        return 0;
    }
    
    // Check for HTTP methods
    if ((data[0] == 'G' && data[1] == 'E' && data[2] == 'T') ||
        (data[0] == 'P' && data[1] == 'O' && data[2] == 'S') ||
        (data[0] == 'P' && data[1] == 'U' && data[2] == 'T') ||
        (data[0] == 'H' && data[1] == 'E' && data[2] == 'A') ||
        (data[0] == 'D' && data[1] == 'E' && data[2] == 'L')) {
        bpf_printk("HTTP method detected: %c%c%c", data[0], data[1], data[2]);
        return 1;
    }
    
    // Check for HTTP response
    if (len >= 4 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') {
        bpf_printk("HTTP response detected");
        return 1;
    }
    
    return 0;
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
            // Check if this looks like HTTP traffic
            if (is_http_data(event.data, event.data_len)) {
                bpf_printk("SSL_read: HTTP traffic detected");
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            }
        }
    } else {
        bpf_printk("SSL_read: invalid buffer");
    }

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
            // Check if this looks like HTTP traffic
            if (is_http_data(event.data, event.data_len)) {
                bpf_printk("SSL_write: HTTP traffic detected");
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            }
        }
    } else {
        bpf_printk("SSL_write: invalid buffer");
    }

    return 0;
}

// Trace TCP receive
SEC("kprobe/tcp_recvmsg")
int trace_tcp_recv(struct pt_regs *ctx) {
    http_event_t event = {};
    struct sock *sk = (struct sock *)ctx->rdi;
    void *buf = (void *)ctx->rsi;
    size_t len = (size_t)ctx->rdx;

    // Get process and thread IDs
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SOCKET_READ;
    event.conn_id = (__u32)(unsigned long)sk;

    // Log debug information
    bpf_printk("TCP recv: pid=%d sk=%p len=%d", event.pid, sk, len);

    // Copy data if buffer is valid
    if (buf != NULL) {
        // Ensure we don't exceed our buffer size
        if (len > MAX_MSG_SIZE) {
            len = MAX_MSG_SIZE;
        }
        event.data_len = len;
        if (safe_read_user(event.data, len, buf) < 0) {
            event.data_len = 0;
            bpf_printk("TCP recv: failed to read data");
        } else {
            // Check if this looks like HTTP traffic
            if (is_http_data(event.data, event.data_len)) {
                bpf_printk("TCP recv: HTTP traffic detected, sending event");
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            }
        }
    }

    return 0;
}

// Trace TCP send
SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx) {
    http_event_t event = {};
    struct sock *sk = (struct sock *)ctx->rdi;
    void *buf = (void *)ctx->rsi;
    size_t len = (size_t)ctx->rdx;

    // Get process and thread IDs
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SOCKET_WRITE;
    event.conn_id = (__u32)(unsigned long)sk;

    // Log debug information
    bpf_printk("TCP send: pid=%d sk=%p len=%d", event.pid, sk, len);

    // Copy data if buffer is valid
    if (buf != NULL) {
        // Ensure we don't exceed our buffer size
        if (len > MAX_MSG_SIZE) {
            len = MAX_MSG_SIZE;
        }
        event.data_len = len;
        if (safe_read_user(event.data, len, buf) < 0) {
            event.data_len = 0;
            bpf_printk("TCP send: failed to read data");
        } else {
            // Check if this looks like HTTP traffic
            if (is_http_data(event.data, event.data_len)) {
                bpf_printk("TCP send: HTTP traffic detected, sending event");
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            }
        }
    }

    return 0;
}

// Trace TCP connect
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)ctx->rdi;
    struct sockaddr_in *addr = (struct sockaddr_in *)ctx->rsi;
    http_event_t event = {};

    // Get process and thread IDs
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SOCKET_WRITE;
    event.conn_id = (__u32)(unsigned long)sk;

    // Log debug information
    bpf_printk("tcp_v4_connect: pid=%d sk=%p addr=%p", event.pid, sk, addr);

    // Update connection state
    __u32 *state = bpf_map_lookup_elem(&conn_state, &event.conn_id);
    if (!state) {
        __u32 new_state = 1;
        bpf_map_update_elem(&conn_state, &event.conn_id, &new_state, BPF_ANY);
        bpf_printk("tcp_v4_connect: new connection state created");
    }

    return 0;
}

// Explicitly set program version to avoid vDSO lookup
__u32 _version SEC("version") = 0xFFFFFFFE;

char _license[] SEC("license") = "GPL";
