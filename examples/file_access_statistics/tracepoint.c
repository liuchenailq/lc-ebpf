// +build ignore

#include "common.h"

#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct open_info
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    /* data */
    int syscall_nr;
    char * filename;
    int flags;
    unsigned short mode
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct open_info *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct open_info *info){
    bpf_perf_event_output(NULL, &events, BPF_F_CURRENT_CPU, info, sizeof(open_info));
}


