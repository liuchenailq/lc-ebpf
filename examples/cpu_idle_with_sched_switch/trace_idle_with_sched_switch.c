// +build ignore

#include "bpf_tracing.h"
#include "common.h"
#include <linux/sched.h>

char __license[] SEC("license") = "Dual MIT/GPL";

 #define MAX_MAP_ENTRIES 20

// start idle time of per-cpu
 struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __uint(max_entries, MAX_MAP_ENTRIES);
   __type(key, __u32);
   __type(value, __u64);
 } start_idle_time_map SEC(".maps");

// idle duration time of per-cpu
 struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __uint(max_entries, MAX_MAP_ENTRIES);
   __type(key, __u32);
   __type(value, __u64);
 } idle_duration_time_map SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct syscalls_sched_switch_args {
  unsigned long long pad;
  char prev_comm[16];
  int prev_pid;
  int prev_prio;
  long long prev_state;
  char next_comm[16];
  int next_pid;
  int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct syscalls_sched_switch_args *ctx) {
      __u32 cpu = bpf_get_smp_processor_id();
      __u64 now = bpf_ktime_get_ns();
      int prev_pid = ctx->prev_pid;
      int next_pid = ctx->next_pid;
      if (next_pid == 0){
            // update start_idle_time_map
            __u64 *value = bpf_map_lookup_elem(&start_idle_time_map, &cpu);
            if (value) {
              bpf_map_update_elem(&start_idle_time_map, &cpu, &now,
                                  BPF_EXIST);
            } else {
              bpf_map_update_elem(&start_idle_time_map, &cpu, &now,
                                  BPF_NOEXIST);
            }
      }
      if (prev_pid == 0){
        // update idle_duration_time_map
        __u64 *start_idle_time = bpf_map_lookup_elem(&start_idle_time_map, &cpu);
        if (start_idle_time) {
            __u64 duration_time = now - *start_idle_time;
            __u64 *value = bpf_map_lookup_elem(&idle_duration_time_map, &cpu);
            if (value) {
                  duration_time = duration_time + *value;
                  bpf_map_update_elem(&idle_duration_time_map, &cpu, &duration_time,
                                      BPF_EXIST);
                } else {
                  bpf_map_update_elem(&idle_duration_time_map, &cpu, &duration_time,
                                      BPF_NOEXIST);
                }
        }
      }


  return 0;
}
