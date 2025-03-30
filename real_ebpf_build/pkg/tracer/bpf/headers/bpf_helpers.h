#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* Basic type definitions */
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;

/* Map type definitions */
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4

/* Other constants */
#define BPF_F_CURRENT_CPU 0xffffffffULL

/* Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* BPF map definition macros - compatible with Cilium bpf2go */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

#define BPF_MAP(_name, _type, _key_size, _value_size, _max_entries) \
struct bpf_map_def _name = { \
    .type = _type, \
    .key_size = _key_size, \
    .value_size = _value_size, \
    .max_entries = _max_entries, \
    .map_flags = 0, \
};

/* PT_REGS structure for uprobe parameters */
struct pt_regs {
    __u64 regs[8];  /* Simplified registers array */
};

/* Parameter access macros */
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])

/* Helper functions called from eBPF programs written in C */
/* BPF_FUNC_* values are placeholders - the actual values
   will be determined by the BPF verifier */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3
#define BPF_FUNC_probe_read 4
#define BPF_FUNC_ktime_get_ns 5
#define BPF_FUNC_trace_printk 6
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_uid_gid 15
#define BPF_FUNC_get_current_comm 16
#define BPF_FUNC_perf_event_output 25
#define BPF_FUNC_probe_read_user 112

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
    (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
                 unsigned long long flags) =
    (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
    (void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
    (void *) BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
    (void *) BPF_FUNC_ktime_get_ns;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
    (void *) BPF_FUNC_get_current_pid_tgid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
    (void *) BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_output)(void *ctx, void *map,
                   unsigned long long flags, void *data,
                   int size) =
    (void *) BPF_FUNC_perf_event_output;
static int (*bpf_probe_read_user)(void *dst, int size, void *unsafe_ptr) =
    (void *) BPF_FUNC_probe_read_user;

#endif /* __BPF_HELPERS_H */
