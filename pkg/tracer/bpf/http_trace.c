//+build ignore

// Force disable vDSO and version checks
#define CORE_DISABLE_VDSO_LOOKUP 1
#define HAVE_NO_VDSO 1

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stddef.h>  // For size_t

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

// Maximum size for our data buffer - must be power of 2
#define MAX_MSG_SIZE 1024

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

// Map to store active file descriptors
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(_Bool));
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_fds SEC(".maps") = {};

// Event types
#define EVENT_TYPE_SSL_READ  1
#define EVENT_TYPE_SSL_WRITE 2
#define EVENT_TYPE_SOCKET_READ  3
#define EVENT_TYPE_SOCKET_WRITE 4
#define EVENT_TYPE_CONNECT 5
#define EVENT_TYPE_CLOSE 6

// Helper function to check if data looks like HTTP
static __always_inline int is_http_data(const char *data, size_t len) {
    if (len < 4) {
        bpf_printk("Data too short for HTTP: %d bytes", len);
        return 0;
    }
    
    // Get process name for debugging
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Log the first few bytes for debugging
    if (len >= 4) {
        unsigned char b1 = data[0], b2 = data[1], b3 = data[2], b4 = data[3];
        // Split the logging into multiple calls
        bpf_printk("Process: %s", comm);
        bpf_printk("Bytes: %02x %02x", b1, b2);
        bpf_printk("Bytes: %02x %02x", b3, b4);
        
        // Split character logging
        char c1 = (b1 >= 32 && b1 <= 126) ? b1 : '.';
        char c2 = (b2 >= 32 && b2 <= 126) ? b2 : '.';
        bpf_printk("Chars: %c%c", c1, c2);
        
        char c3 = (b3 >= 32 && b3 <= 126) ? b3 : '.';
        char c4 = (b4 >= 32 && b4 <= 126) ? b4 : '.';
        bpf_printk("Chars: %c%c", c3, c4);
    }
    
    // Check for HTTP methods (common methods first)
    if (len >= 4) {
        // GET request
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') {
            bpf_printk("HTTP GET request from %s", comm);
            return 1;
        }
        // POST request
        if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
            bpf_printk("HTTP POST request from %s", comm);
            return 1;
        }
        // HTTP response
        if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') {
            bpf_printk("HTTP response from %s", comm);
            return 1;
        }
        // JSON response (common for APIs)
        if (data[0] == '{') {
            bpf_printk("JSON response from %s", comm);
            return 1;
        }
    }
    
    return 0;
}

// Trace accept4 syscall
SEC("kprobe/sys_accept4")
int trace_accept4(struct pt_regs *ctx) {
    http_event_t event = {};
    int sockfd = (int)ctx->rdi;
    
    // Get process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_CONNECT;
    event.conn_id = sockfd;

    // Get process name for debugging
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Debug log
    bpf_printk("accept4 from %s (pid=%d sockfd=%d)", comm, event.pid, sockfd);

    // Store the file descriptor as active
    _Bool t = 1;
    bpf_map_update_elem(&active_fds, &sockfd, &t, BPF_ANY);

    return 0;
}

// Trace write syscall
SEC("kprobe/sys_write")
int trace_write(struct pt_regs *ctx) {
    http_event_t event = {};
    int fd = (int)ctx->rdi;
    void *buf = (void *)ctx->rsi;
    size_t len = (size_t)ctx->rdx;
    
    // Check if this is an active file descriptor
    _Bool *is_active = bpf_map_lookup_elem(&active_fds, &fd);
    if (!is_active) {
        return 0;
    }
    
    // Get process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SOCKET_WRITE;
    event.conn_id = fd;

    // Get process name for debugging
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Debug log
    bpf_printk("write from %s (pid=%d fd=%d len=%d)", comm, event.pid, fd, len);

    // Try to read the data
    if (buf != NULL && len > 0) {
        // Cap the length
        if (len > MAX_MSG_SIZE) {
            len = MAX_MSG_SIZE;
        }
        event.data_len = len;

        // Try to read the data
        if (bpf_probe_read_user(event.data, len, buf) < 0) {
            bpf_printk("write: failed to read buffer");
            return 0;
        }

        // Log the first few bytes for debugging
        if (len >= 4) {
            // Split the logging into two calls
            bpf_printk("write data (1/2): %c%c", event.data[0], event.data[1]);
            bpf_printk("write data (2/2): %c%c", event.data[2], event.data[3]);
        }

        // Check if it's HTTP
        if (is_http_data(event.data, event.data_len)) {
            bpf_printk("write: sending HTTP event from %s", comm);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        }
    }

    return 0;
}

// Trace read syscall
SEC("kprobe/sys_read")
int trace_read(struct pt_regs *ctx) {
    http_event_t event = {};
    int fd = (int)ctx->rdi;
    void *buf = (void *)ctx->rsi;
    size_t len = (size_t)ctx->rdx;
    
    // Check if this is an active file descriptor
    _Bool *is_active = bpf_map_lookup_elem(&active_fds, &fd);
    if (!is_active) {
        return 0;
    }
    
    // Get process info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_SOCKET_READ;
    event.conn_id = fd;

    // Get process name for debugging
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Debug log
    bpf_printk("read from %s (pid=%d fd=%d len=%d)", comm, event.pid, fd, len);

    // Try to read the data
    if (buf != NULL && len > 0) {
        // Cap the length
        if (len > MAX_MSG_SIZE) {
            len = MAX_MSG_SIZE;
        }
        event.data_len = len;

        // Try to read the data
        if (bpf_probe_read_user(event.data, len, buf) < 0) {
            bpf_printk("read: failed to read buffer");
            return 0;
        }

        // Log the first few bytes for debugging
        if (len >= 4) {
            // Split the logging into two calls
            bpf_printk("read data (1/2): %c%c", event.data[0], event.data[1]);
            bpf_printk("read data (2/2): %c%c", event.data[2], event.data[3]);
        }

        // Check if it's HTTP
        if (is_http_data(event.data, event.data_len)) {
            bpf_printk("read: sending HTTP event from %s", comm);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        }
    }

    return 0;
}

// Trace close syscall
SEC("kprobe/sys_close")
int trace_close(struct pt_regs *ctx) {
    int fd = (int)ctx->rdi;
    
    // Check if this is an active file descriptor
    _Bool *is_active = bpf_map_lookup_elem(&active_fds, &fd);
    if (!is_active) {
        return 0;
    }
    
    // Get process name for debugging
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Debug log
    bpf_printk("close from %s (fd=%d)", comm, fd);

    // Remove the file descriptor from active list
    bpf_map_delete_elem(&active_fds, &fd);

    return 0;
}

// Explicitly set program version to avoid vDSO lookup
__u32 _version SEC("version") = 0xFFFFFFFE;

char _license[] SEC("license") = "GPL";
