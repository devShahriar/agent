//+build ignore

// Force disable vDSO and version checks
#define CORE_DISABLE_VDSO_LOOKUP 1
#define HAVE_NO_VDSO 1

// Basic type definitions to avoid problematic includes
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef unsigned long size_t;

// Define NULL since we don't include standard headers
#define NULL ((void *)0)

// BPF map types and helpers
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_ANY 0
#define BPF_F_CURRENT_CPU 0xffffffffULL

// For maps
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Explicitly define the trace event raw structures
struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long id;
    long ret;
};

// Custom attribute declarations
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

// Maximum size for data buffer
#define EVENT_BUF_SIZE 256

// Event types
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

// Declare required maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct read_args_t));
    __uint(max_entries, 1024);
} read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct http_event_t));
    __uint(max_entries, 1);
} event_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct socket_key));
    __uint(value_size, sizeof(_Bool));
    __uint(max_entries, 10240);
} active_sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct socket_key));
    __uint(value_size, sizeof(struct socket_info));
    __uint(max_entries, 10240);
} socket_info SEC(".maps");

// Helper function declarations for BPF
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)4;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *)25;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;

// Zero value for maps
__u32 zero = 0;

// Helper macro for debug printing
#define bpf_printk(fmt, ...)                           \
({                                                     \
    char ____fmt[] = fmt;                              \
    bpf_trace_printk(____fmt, sizeof(____fmt),         \
             ##__VA_ARGS__);                           \
})

// Helper function to check if data looks like HTTP
static __always_inline int is_http_data(const char *data, size_t len) {
    if (len < 4) {
        return 0;
    }
    
    // HTTP request methods
    if (len >= 3 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T')
        return 1;
    if (len >= 4 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T')
        return 1;
    if (len >= 3 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T')
        return 1;
    if (len >= 4 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D')
        return 1;
    
    // HTTP responses
    if (len >= 4 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P')
        return 1;
    
    return 0;
}

// Trace accept4 syscall - Mark socket as active
SEC("tracepoint/syscalls/sys_enter_accept4")
int TraceAccept4(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("TraceAccept4: pid=%d", pid);
    return 0;
}

// Exit handler for accept4
SEC("tracepoint/syscalls/sys_exit_accept4")
int TraceAccept4Exit(struct trace_event_raw_sys_exit *ctx) {
    int ret_fd = ctx->ret;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (ret_fd < 0) {
        return 0;
    }
    
    bpf_printk("TraceAccept4Exit: pid=%d ret_fd=%d", pid, ret_fd);
    
    struct socket_key key = {
        .pid = pid,
        .fd = ret_fd
    };
    
    _Bool is_active = 1;
    bpf_map_update_elem(&active_sockets, &key, &is_active, BPF_ANY);
    
    struct socket_info info = {
        .created_ns = bpf_ktime_get_ns(),
        .parent_fd = 0,
        .is_server = 1
    };
    bpf_map_update_elem(&socket_info, &key, &info, BPF_ANY);
    
    return 0;
}

// Trace connect syscall - Mark socket as active for clients
SEC("tracepoint/syscalls/sys_enter_connect")
int TraceConnect(struct trace_event_raw_sys_enter *ctx) {
    int sockfd = ctx->args[0];
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (sockfd < 0) {
        return 0;
    }
    
    bpf_printk("TraceConnect: pid=%d sockfd=%d", pid, sockfd);
    
    struct socket_key key = {
        .pid = pid,
        .fd = sockfd
    };
    
    _Bool is_active = 1;
    bpf_map_update_elem(&active_sockets, &key, &is_active, BPF_ANY);
    
    struct socket_info info = {
        .created_ns = bpf_ktime_get_ns(),
        .parent_fd = 0,
        .is_server = 0
    };
    bpf_map_update_elem(&socket_info, &key, &info, BPF_ANY);
    
    return 0;
}

// Trace write syscall - Capture HTTP requests
SEC("tracepoint/syscalls/sys_enter_write")
int TraceWrite(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    char *buf = (char *)ctx->args[1];
    size_t len = ctx->args[2];
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct socket_key key = {
        .pid = pid,
        .fd = fd
    };
    
    _Bool *is_active = bpf_map_lookup_elem(&active_sockets, &key);
    if (!is_active) {
        return 0;
    }
    
    if (buf == NULL || len == 0 || len > EVENT_BUF_SIZE) {
        return 0;
    }
    
    struct http_event_t *event = bpf_map_lookup_elem(&event_storage, &zero);
    if (!event) {
        return 0;
    }
    
    event->pid = pid;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->fd = fd;
    event->type = EVENT_SOCKET_WRITE;
    event->data_len = len < EVENT_BUF_SIZE ? len : EVENT_BUF_SIZE;
    
    if (bpf_probe_read_user(event->data, event->data_len, buf) < 0) {
        return 0;
    }
    
    if (is_http_data(event->data, event->data_len)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
}

// Trace read syscall - Capture HTTP responses 
SEC("tracepoint/syscalls/sys_enter_read")
int TraceRead(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    char *buf = (char *)ctx->args[1];
    size_t len = ctx->args[2];
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct socket_key key = {
        .pid = pid,
        .fd = fd
    };
    
    _Bool *is_active = bpf_map_lookup_elem(&active_sockets, &key);
    if (!is_active) {
        return 0;
    }
    
    struct read_args_t args = {
        .pid = pid,
        .fd = fd,
        .buf = buf,
        .len = len
    };
    
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
    
    return 0;
}

// Return probe for read syscall
SEC("tracepoint/syscalls/sys_exit_read")
int TraceReadRet(struct trace_event_raw_sys_exit *ctx) {
    size_t bytes_read = ctx->ret;
    __u64 id = bpf_get_current_pid_tgid();
    
    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &id);
    if (!args || bytes_read <= 0) {
        if (args) {
            bpf_map_delete_elem(&read_args_map, &id);
        }
        return 0;
    }
    
    struct http_event_t *event = bpf_map_lookup_elem(&event_storage, &zero);
    if (!event) {
        bpf_map_delete_elem(&read_args_map, &id);
        return 0;
    }
    
    event->pid = args->pid;
    event->tid = id & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->fd = args->fd;
    event->type = EVENT_SOCKET_READ;
    event->data_len = bytes_read < EVENT_BUF_SIZE ? bytes_read : EVENT_BUF_SIZE;
    
    if (bpf_probe_read_user(event->data, event->data_len, args->buf) < 0) {
        bpf_map_delete_elem(&read_args_map, &id);
        return 0;
    }
    
    if (is_http_data(event->data, event->data_len)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    bpf_map_delete_elem(&read_args_map, &id);
    return 0;
}

// Trace close syscall - Remove from active sockets
SEC("tracepoint/syscalls/sys_enter_close")
int TraceClose(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct socket_key key = {
        .pid = pid,
        .fd = fd
    };
    
    _Bool *is_active = bpf_map_lookup_elem(&active_sockets, &key);
    if (is_active) {
        bpf_map_delete_elem(&active_sockets, &key);
        bpf_map_delete_elem(&socket_info, &key);
    }
    
    return 0;
}

// License
char _license[] SEC("license") = "GPL";
