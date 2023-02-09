// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event{
    u32 cpu;
    u64 now;
    u32 flag;
}

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/do_idle")
int kprobe_do_idle(struct pt_regs *ctx){
    // cpu enters idle state
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 now = bpf_ktime_get_ns();
    struct event event;
    event.cpu = cpu
    event.now = now
    event.flag = 1
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                              sizeof(event));
    return 0;
}

SEC("kprobe/schedule_idle")
int kprobe_schedule_idle(struct pt_regs *ctx){
    // cpu leaves idle state
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 now = bpf_ktime_get_ns();
    event.cpu = cpu
    event.now = now
    event.flag = 0
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                              sizeof(event));
    return 0;
}
