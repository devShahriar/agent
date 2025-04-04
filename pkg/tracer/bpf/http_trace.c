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

// Connection state structure
struct conn_state {
    __u32 pid;
    __u32 tid;
    __u64 start_time;
    __u8 is_active;
} __attribute__((packed));

// Map to store events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps") = {};

// Per-CPU array map for event storage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(http_event_t));
    __uint(max_entries, 1);
} event_storage SEC(".maps") = {};

// Map to store connection state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct conn_state));
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
#define EVENT_TYPE_SSL_READ    1  // Response
#define EVENT_TYPE_SSL_WRITE   2  // Request
#define EVENT_TYPE_SOCKET_READ 3  // Response
#define EVENT_TYPE_SOCKET_WRITE 4 // Request
#define EVENT_TYPE_CONNECT     5  // New connection
#define EVENT_TYPE_CLOSE       6  // Connection closed
#define EVENT_TYPE_HTTP_GET    7  // HTTP GET request
#define EVENT_TYPE_HTTP_POST   8  // HTTP POST request
#define EVENT_TYPE_HTTP_PUT    9  // HTTP PUT request
#define EVENT_TYPE_HTTP_DELETE 10 // HTTP DELETE request
#define EVENT_TYPE_HTTP_RESP   11 // HTTP response

// Helper function to check if data looks like HTTP
static __always_inline int is_http_data(const char *data, size_t len) {
    if (len < 4) {
        return 0;
    }
    
    // Check for HTTP methods (GET, POST, PUT, DELETE, etc.)
    if (len >= 4) {
        // GET request
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') {
            return 1;
        }
        // POST request
        if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
            return 1;
        }
        // PUT request
        if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') {
            return 1;
        }
        // DELETE request
        if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E') {
            return 1;
        }
        // HTTP response
        if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') {
            return 1;
        }
    }
    
    // Check for common HTTP headers
    if (len >= 6) {
        // Content-Type
        if (data[0] == 'C' && data[1] == 'o' && data[2] == 'n' && 
            data[3] == 't' && data[4] == 'e' && data[5] == 'n') {
            return 1;
        }
        // Host header
        if (data[0] == 'H' && data[1] == 'o' && data[2] == 's' && 
            data[3] == 't' && data[4] == ':' && data[5] == ' ') {
            return 1;
        }
    }
    
    return 0;
}

// Trace accept4 syscall
SEC("kprobe/sys_accept4")
int trace_accept4(struct pt_regs *ctx) {
    __u32 zero = 0;
    http_event_t *event = bpf_map_lookup_elem(&event_storage, &zero);
    if (!event) {
        return 0;
    }

    int sockfd = (int)ctx->rdi;
    
    // Get process info
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = (__u32)bpf_get_current_pid_tgid();
    event->timestamp = bpf_ktime_get_ns();
    event->type = EVENT_TYPE_CONNECT;
    event->conn_id = sockfd;
    event->data_len = 0;

    // Store connection state
    struct conn_state state = {
        .pid = event->pid,
        .tid = event->tid,
        .start_time = event->timestamp,
        .is_active = 1
    };
    bpf_map_update_elem(&conn_state, &sockfd, &state, BPF_ANY);

    // Store the file descriptor as active
    _Bool t = 1;
    bpf_map_update_elem(&active_fds, &sockfd, &t, BPF_ANY);

    return 0;
}

// Trace write syscall
SEC("kprobe/sys_write")
int trace_write(struct pt_regs *ctx) {
    __u32 zero = 0;
    http_event_t *event = bpf_map_lookup_elem(&event_storage, &zero);
    if (!event) {
        return 0;
    }

    int fd = (int)ctx->rdi;
    void *buf = (void *)ctx->rsi;
    size_t len = (size_t)ctx->rdx;
    
    // Check if this is an active file descriptor
    _Bool *is_active = bpf_map_lookup_elem(&active_fds, &fd);
    if (!is_active) {
        return 0;
    }
    
    // Get process info
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = (__u32)bpf_get_current_pid_tgid();
    event->timestamp = bpf_ktime_get_ns();
    event->type = EVENT_TYPE_SOCKET_WRITE;
    event->conn_id = fd;
    event->data_len = 0;

    // Get process name for debugging
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Debug log
    bpf_printk("write from %s", comm);
    bpf_printk("pid=%d fd=%d", event->pid, fd);
    bpf_printk("len=%d", len);

    // Try to read the data
    if (buf != NULL && len > 0) {
        // Cap the length
        if (len > MAX_MSG_SIZE) {
            len = MAX_MSG_SIZE;
        }
        event->data_len = len;

        // Try to read the data
        if (bpf_probe_read_user(event->data, len, buf) < 0) {
            bpf_printk("write: failed to read buffer");
            return 0;
        }

        // Log the first few bytes for debugging
        if (len >= 4) {
            // Split the logging into two calls
            bpf_printk("write data (1/2): %c%c", event->data[0], event->data[1]);
            bpf_printk("write data (2/2): %c%c", event->data[2], event->data[3]);
        }

        // Check if it's HTTP
        if (is_http_data(event->data, event->data_len)) {
            bpf_printk("write: sending HTTP event from %s", comm);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
        }
    }

    return 0;
}

// Trace read syscall
SEC("kprobe/sys_read")
int trace_read(struct pt_regs *ctx) {
    __u32 zero = 0;
    http_event_t *event = bpf_map_lookup_elem(&event_storage, &zero);
    if (!event) {
        return 0;
    }

    int fd = (int)ctx->rdi;
    void *buf = (void *)ctx->rsi;
    size_t len = (size_t)ctx->rdx;
    
    // Check if this is an active file descriptor
    _Bool *is_active = bpf_map_lookup_elem(&active_fds, &fd);
    if (!is_active) {
        return 0;
    }
    
    // Get process info
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = (__u32)bpf_get_current_pid_tgid();
    event->timestamp = bpf_ktime_get_ns();
    event->type = EVENT_TYPE_SOCKET_READ;
    event->conn_id = fd;
    event->data_len = 0;

    // Get process name for debugging
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Debug log
    bpf_printk("read from %s", comm);
    bpf_printk("pid=%d fd=%d", event->pid, fd);
    bpf_printk("len=%d", len);

    // Try to read the data
    if (buf != NULL && len > 0) {
        // Cap the length
        if (len > MAX_MSG_SIZE) {
            len = MAX_MSG_SIZE;
        }
        event->data_len = len;

        // Try to read the data
        if (bpf_probe_read_user(event->data, len, buf) < 0) {
            bpf_printk("read: failed to read buffer");
            return 0;
        }

        // Log the first few bytes for debugging
        if (len >= 4) {
            // Split the logging into two calls
            bpf_printk("read data (1/2): %c%c", event->data[0], event->data[1]);
            bpf_printk("read data (2/2): %c%c", event->data[2], event->data[3]);
        }

        // Check if it's HTTP
        if (is_http_data(event->data, event->data_len)) {
            bpf_printk("read: sending HTTP event from %s", comm);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
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
    
    // Remove connection state
    bpf_map_delete_elem(&conn_state, &fd);
    
    // Remove from active file descriptors
    bpf_map_delete_elem(&active_fds, &fd);

    return 0;
}

// Explicitly set program version to avoid vDSO lookup
__u32 _version SEC("version") = 0xFFFFFFFE;

char _license[] SEC("license") = "GPL";
