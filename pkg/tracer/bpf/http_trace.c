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

// Max buffer size for data
#define EVENT_BUF_SIZE 256

// Process info structure
struct process_info {
    __u32 pid;
    __u32 ppid;
    char comm[16];
} __attribute__((packed));

// Event types (expanded)
#define EVENT_SOCKET_READ    1  // Socket read event (HTTP response)
#define EVENT_SOCKET_WRITE   2  // Socket write event (HTTP request)
#define EVENT_SOCKET_ACCEPT  3  // Socket accept event
#define EVENT_SOCKET_CONNECT 4  // Socket connect event
#define EVENT_SOCKET_CLOSE   5  // Socket close event
#define EVENT_SSL_READ       6  // SSL read event (HTTP response)
#define EVENT_SSL_WRITE      7  // SSL write event (HTTP request)

// HTTP event structure
struct http_event_t {
    __u32 pid;           // Process ID
    __u32 tid;           // Thread ID
    __u64 timestamp;     // Timestamp
    __u32 fd;            // File descriptor
    __u8 type;           // Event type
    __u32 data_len;      // Length of data
    char data[EVENT_BUF_SIZE]; // Data buffer
};

// Zero value for maps
__u32 zero = 0;

// Connection state structure
struct conn_state {
    __u32 pid;
    __u32 tid;
    __u64 start_time;
    __u8 is_active;
} __attribute__((packed));

// Structure to identify sockets
struct socket_key {
    __u32 pid;
    __u32 fd;
};

// Socket info structure
struct socket_info {
    __u64 created_ns;
    __u32 parent_fd;
    __u8 is_server;
};

// Read arguments for return probe
struct read_args_t {
    __u32 pid;
    __u32 fd;
    void *buf;
    size_t len;
};

// Map to store read arguments for return probes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct read_args_t));
    __uint(max_entries, 1024);
} read_args_map SEC(".maps") = {};

// Map to store events for userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps") = {};

// Per-CPU array for event storage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct http_event_t));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
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

// Map to store active sockets by process ID and file descriptor
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct socket_key));
    __uint(value_size, sizeof(_Bool));
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_sockets SEC(".maps") = {};

// Map to track socket state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct socket_key));
    __uint(value_size, sizeof(struct socket_info));
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} socket_info SEC(".maps") = {};

// Architecture-independent register access
#if defined(__TARGET_ARCH_x86)
#define SYSCALL_GET_PARM1(x) ((x)->di)
#define SYSCALL_GET_PARM2(x) ((x)->si)
#define SYSCALL_GET_PARM3(x) ((x)->dx)
#define SYSCALL_GET_RETURN(x) ((x)->ax)
#elif defined(__TARGET_ARCH_arm64)
#define SYSCALL_GET_PARM1(x) (((unsigned long *)(x))[0])
#define SYSCALL_GET_PARM2(x) (((unsigned long *)(x))[1])
#define SYSCALL_GET_PARM3(x) (((unsigned long *)(x))[2])
#define SYSCALL_GET_RETURN(x) (((unsigned long *)(x))[0])
#else
#define SYSCALL_GET_PARM1(x) BPF_CORE_READ(x, args[0])
#define SYSCALL_GET_PARM2(x) BPF_CORE_READ(x, args[1])
#define SYSCALL_GET_PARM3(x) BPF_CORE_READ(x, args[2])
#define SYSCALL_GET_RETURN(x) BPF_CORE_READ(x, args[0])
#endif

// Helper function to check if data looks like HTTP with improved detection
static __always_inline int is_http_data(const char *data, size_t len) {
    bpf_printk("is_http_data: data length = %d", len);

    if (len < 4) {
        bpf_printk("is_http_data: data too short (%d bytes)", len);
        return 0;
    }
    
    // Log the first 16 bytes of data
    if (len >= 16) {
        bpf_printk("is_http_data: data = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
    } else {
        bpf_printk("is_http_data: data = %02x %02x %02x %02x",
            data[0], data[1], data[2], data[3]);
    }
    
    // HTTP request methods (complete list)
    if (len >= 3 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
        bpf_printk("is_http_data: found GET request");
        return 1;
    }
    if (len >= 4 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
        bpf_printk("is_http_data: found POST request");
        return 1;
    }
    if (len >= 3 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T') {
        bpf_printk("is_http_data: found PUT request");
        return 1;
    }
    if (len >= 6 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E') {
        bpf_printk("is_http_data: found DELETE request");
        return 1;
    }
    if (len >= 4 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') {
        bpf_printk("is_http_data: found HEAD request");
        return 1;
    }
    if (len >= 7 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S') {
        bpf_printk("is_http_data: found OPTIONS request");
        return 1;
    }
    if (len >= 5 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && data[4] == 'H') {
        bpf_printk("is_http_data: found PATCH request");
        return 1;
    }
    
    // HTTP responses
    if (len >= 4 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') {
        bpf_printk("is_http_data: found HTTP response");
        return 1;
    }
    
    // HTTP headers (more comprehensive)
    if (len >= 16 && data[0] == 'C' && data[1] == 'o' && data[2] == 'n' && data[3] == 't' && data[4] == 'e' && data[5] == 'n' && data[6] == 't' && data[7] == '-') {
        bpf_printk("is_http_data: found Content header");
        return 1;
    }
    if (len >= 6 && data[0] == 'H' && data[1] == 'o' && data[2] == 's' && data[3] == 't' && data[4] == ':' && data[5] == ' ') {
        bpf_printk("is_http_data: found Host header");
        return 1;
    }
    if (len >= 15 && data[0] == 'A' && data[1] == 'c' && data[2] == 'c' && data[3] == 'e' && data[4] == 'p' && data[5] == 't') {
        bpf_printk("is_http_data: found Accept header");
        return 1;
    }
    if (len >= 13 && data[0] == 'U' && data[1] == 's' && data[2] == 'e' && data[3] == 'r' && data[4] == '-' && data[5] == 'A' && data[6] == 'g' && data[7] == 'e' && data[8] == 'n' && data[9] == 't') {
        bpf_printk("is_http_data: found User-Agent header");
        return 1;
    }
    if (len >= 13 && data[0] == 'C' && data[1] == 'o' && data[2] == 'n' && data[3] == 'n' && data[4] == 'e' && data[5] == 'c' && data[6] == 't' && data[7] == 'i' && data[8] == 'o' && data[9] == 'n') {
        bpf_printk("is_http_data: found Connection header");
        return 1;
    }
    
    // Try to detect JSON payloads which might be API calls
    if (len >= 2 && data[0] == '{' && data[len-1] == '}') {
        bpf_printk("is_http_data: found JSON payload");
        return 1;
    }
    
    bpf_printk("is_http_data: no HTTP data detected");
    return 0;
}

// Trace accept4 syscall - Mark socket as active
SEC("kprobe/sys_accept4")
int trace_accept4(struct pt_regs *ctx) {
    // Extract parameters
    int sockfd = (int)SYSCALL_GET_PARM1(ctx);
    int ret_fd = (int)SYSCALL_GET_RETURN(ctx);
    
    // Skip invalid file descriptors
    if (ret_fd < 0) {
        return 0;
    }
    
    bpf_printk("trace_accept4: pid=%d sockfd=%d ret_fd=%d", bpf_get_current_pid_tgid() >> 32, sockfd, ret_fd);

    // Create socket key for child socket
    struct socket_key child_key = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .fd = ret_fd
    };
    
    // Mark as active socket (HTTP server)
    _Bool is_active = 1;
    bpf_map_update_elem(&active_sockets, &child_key, &is_active, BPF_ANY);
    
    // Initialize socket info
    struct socket_info sinfo = {
        .created_ns = bpf_ktime_get_ns(),
        .parent_fd = sockfd,
        .is_server = 1
    };
    bpf_map_update_elem(&socket_info, &child_key, &sinfo, BPF_ANY);
    
    bpf_printk("trace_accept4: added socket pid=%d fd=%d to active sockets", child_key.pid, child_key.fd);
    
    return 0;
}

// Trace connect syscall - Mark socket as active for clients
SEC("kprobe/sys_connect")
int trace_connect(struct pt_regs *ctx) {
    // Extract parameters
    int sockfd = (int)SYSCALL_GET_PARM1(ctx);
    
    // Skip invalid file descriptors
    if (sockfd < 0) {
        return 0;
    }
    
    bpf_printk("trace_connect: pid=%d sockfd=%d", bpf_get_current_pid_tgid() >> 32, sockfd);

    // Create socket key
    struct socket_key key = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .fd = sockfd
    };
    
    // Mark as active socket (HTTP client)
    _Bool is_active = 1;
    bpf_map_update_elem(&active_sockets, &key, &is_active, BPF_ANY);
    
    // Initialize socket info
    struct socket_info sinfo = {
        .created_ns = bpf_ktime_get_ns(),
        .parent_fd = 0,
        .is_server = 0
    };
    bpf_map_update_elem(&socket_info, &key, &sinfo, BPF_ANY);
    
    bpf_printk("trace_connect: added socket pid=%d fd=%d to active sockets", key.pid, key.fd);
    
    return 0;
}

// Trace write syscall - Capture HTTP requests
SEC("kprobe/sys_write")
int trace_write(struct pt_regs *ctx) {
    // Extract parameters
    int fd = (int)SYSCALL_GET_PARM1(ctx);
    char *buf = (char *)SYSCALL_GET_PARM2(ctx);
    size_t len = (size_t)SYSCALL_GET_PARM3(ctx);
    
    // Get current PID and create key
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct socket_key key = {
        .pid = pid,
        .fd = fd
    };
    
    // Check if this is an active socket we're monitoring
    _Bool *is_active = bpf_map_lookup_elem(&active_sockets, &key);
    if (!is_active) {
        return 0;
    }
    
    bpf_printk("trace_write: pid=%d fd=%d len=%d (active socket)", pid, fd, len);
    
    // Early return if no data
    if (buf == NULL || len == 0 || len > EVENT_BUF_SIZE) {
        bpf_printk("trace_write: invalid buffer or length: buf=%p, len=%d", buf, len);
        return 0;
    }
    
    // Get event from per-CPU array
    struct http_event_t *event = bpf_map_lookup_elem(&event_storage, &zero);
    if (!event) {
        bpf_printk("trace_write: failed to get event from storage");
        return 0;
    }
    
    // Initialize event fields
    event->pid = pid;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->fd = fd;
    event->type = EVENT_SOCKET_WRITE; // This is generally a request
    event->data_len = len < EVENT_BUF_SIZE ? len : EVENT_BUF_SIZE;
    
    // Read the data from user space
    int ret = bpf_probe_read_user(event->data, event->data_len, buf);
    if (ret < 0) {
        bpf_printk("trace_write: failed to read user data: %d", ret);
        return 0;
    }
    
    // Check if it's HTTP
    if (is_http_data(event->data, event->data_len)) {
        bpf_printk("trace_write: found HTTP data for pid=%d fd=%d len=%d", event->pid, fd, len);
        ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
        bpf_printk("trace_write: bpf_perf_event_output returned %d", ret);
    } else {
        bpf_printk("trace_write: not HTTP data for pid=%d fd=%d len=%d", event->pid, fd, len);
    }
    
    return 0;
}

// Trace read syscall - Capture HTTP responses 
SEC("kprobe/sys_read")
int trace_read(struct pt_regs *ctx) {
    // Extract parameters before the syscall executes
    int fd = (int)SYSCALL_GET_PARM1(ctx);
    char *buf = (char *)SYSCALL_GET_PARM2(ctx);
    size_t len = (size_t)SYSCALL_GET_PARM3(ctx);
    
    // Get current PID and create key
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct socket_key key = {
        .pid = pid,
        .fd = fd
    };
    
    // Check if this is an active socket we're monitoring
    _Bool *is_active = bpf_map_lookup_elem(&active_sockets, &key);
    if (!is_active) {
        return 0;
    }
    
    bpf_printk("trace_read: pid=%d fd=%d len=%d (active socket)", pid, fd, len);
    
    // We can't read the buffer before the syscall executes,
    // so attach a return probe to read after
    struct read_args_t read_args = {
        .pid = pid,
        .fd = fd,
        .buf = buf,
        .len = len
    };
    
    // Store the args for the return probe
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&read_args_map, &id, &read_args, BPF_ANY);
    
    return 0;
}

// Return probe for read syscall
SEC("kretprobe/sys_read")
int trace_read_ret(struct pt_regs *ctx) {
    // Get the return value (bytes read)
    size_t bytes_read = (size_t)SYSCALL_GET_RETURN(ctx);
    __u64 id = bpf_get_current_pid_tgid();
    
    // Retrieve the stored args
    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &id);
    if (!args || bytes_read <= 0) {
        if (args) {
            bpf_map_delete_elem(&read_args_map, &id);
        }
        return 0;
    }
    
    bpf_printk("trace_read_ret: pid=%d fd=%d bytes_read=%d", args->pid, args->fd, bytes_read);
    
    // Get event from per-CPU array
    struct http_event_t *event = bpf_map_lookup_elem(&event_storage, &zero);
    if (!event) {
        bpf_printk("trace_read_ret: failed to get event from storage");
        bpf_map_delete_elem(&read_args_map, &id);
        return 0;
    }
    
    // Initialize event fields
    event->pid = args->pid;
    event->tid = id & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->fd = args->fd;
    event->type = EVENT_SOCKET_READ; // This is generally a response
    event->data_len = bytes_read < EVENT_BUF_SIZE ? bytes_read : EVENT_BUF_SIZE;
    
    // Read the data that was read into the user's buffer
    int ret = bpf_probe_read_user(event->data, event->data_len, args->buf);
    if (ret < 0) {
        bpf_printk("trace_read_ret: failed to read user data: %d", ret);
        bpf_map_delete_elem(&read_args_map, &id);
        return 0;
    }
    
    // Check if it's HTTP
    if (is_http_data(event->data, event->data_len)) {
        bpf_printk("trace_read_ret: found HTTP data for pid=%d fd=%d len=%d", event->pid, args->fd, bytes_read);
        ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
        bpf_printk("trace_read_ret: bpf_perf_event_output returned %d", ret);
    } else {
        bpf_printk("trace_read_ret: not HTTP data for pid=%d fd=%d len=%d", event->pid, args->fd, bytes_read);
    }
    
    // Clean up
    bpf_map_delete_elem(&read_args_map, &id);
    
    return 0;
}

// Trace close syscall - Remove from active sockets
SEC("kprobe/sys_close")
int trace_close(struct pt_regs *ctx) {
    int fd = (int)SYSCALL_GET_PARM1(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct socket_key key = {
        .pid = pid,
        .fd = fd
    };
    
    // Check if this fd is in our active set
    _Bool *is_active = bpf_map_lookup_elem(&active_sockets, &key);
    if (is_active) {
        bpf_printk("trace_close: pid=%d fd=%d (active socket)", pid, fd);
        bpf_map_delete_elem(&active_sockets, &key);
        bpf_map_delete_elem(&socket_info, &key);
    }
    
    return 0;
}

// Explicitly set program version to avoid vDSO lookup
__u32 _version SEC("version") = 0xFFFFFFFE;

char _license[] SEC("license") = "GPL";
