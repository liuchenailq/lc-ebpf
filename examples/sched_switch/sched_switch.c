#include "bpf_tracing.h"
#include "common.h"
#include <linux/sched.h>

char __license[] SEC("license") = "Dual MIT/GPL";

//#define MAX_MAP_ENTRIES 20
//
//// start idle time of per-cpu
//struct {
//  __uint(type, BPF_MAP_TYPE_ARRAY);
//  __uint(max_entries, MAX_MAP_ENTRIES);
//  __type(key, __u32);
//  __type(value, __u64);
//} start_idle_time_map SEC(".maps");
//
//// idle duration time of per-cpu
//struct {
//  __uint(type, BPF_MAP_TYPE_ARRAY);
//  __uint(max_entries, MAX_MAP_ENTRIES);
//  __type(key, __u32);
//  __type(value, __u64);
//} idle_duration_time_map SEC(".maps");

struct event {
  u8 prev_comm[15];
  int prev_pid;
  u8 next_comm[15];
  int next_pid;
  __u32 cpu
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct syscalls_sched_switch_args {
  /* The first 8 bytes is not allowed to read */
  unsigned long pad;

  u8 prev_comm[15];
  int prev_pid;
  int prev_prio;
  long prev_state;
  u8 next_comm[15];
  int next_pid;
  int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct syscalls_sched_switch_args *ctx){
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 now = bpf_ktime_get_ns();
    int prev_pid = ctx->prev_pid;
    int next_pid = ctx->next_pid;
    struct event event;
    event.cpu = cpu;
    event.prev_pid = prev_pid;
    event.next_pid = next_pid;
    char *prev_comm = (char *)(ctx->prev_comm);
    bpf_probe_read_str(&event.prev_comm, sizeof(event.prev_comm), prev_comm);
    char *next_comm = (char *)(ctx->next_comm);
    bpf_probe_read_str(&event.next_comm, sizeof(event.next_comm), next_comm);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                              sizeof(event));
    return 0;
}
