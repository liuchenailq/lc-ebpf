// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 8

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

SEC("kprobe/do_idle")
int kprobe_do_idle(struct pt_regs *ctx) {
  // cpu enters idle state
  __u32 cpu = bpf_get_smp_processor_id();
  __u64 now = bpf_ktime_get_ns();
  __u64 *start_idle_time = bpf_map_lookup_elem(&start_idle_time_map, &cpu);
  if (start_idle_time) {
    bpf_map_update_elem(&start_idle_time_map, &cpu, &now, BPF_EXIST);
  } else {
    bpf_map_update_elem(&start_idle_time_map, &cpu, &now, BPF_NOEXIST);
  }
  return 0;
}

SEC("kprobe/schedule_idle")
int kprobe_schedule_idle(struct pt_regs *ctx) {
  // cpu leaves idle state
  __u32 cpu = bpf_get_smp_processor_id();
  __u64 now = bpf_ktime_get_ns();
  __u64 *start_idle_time = bpf_map_lookup_elem(&start_idle_time_map, &cpu);
  if (start_idle_time) {
    __u64 duration_time = now - *start_idle_time;
    __u64 *value = bpf_map_lookup_elem(&idle_duration_time_map, &cpu);
    if (value) {
      duration_time = duration_time + *value;
      if (cpu == 0) {
        const char fmt_str[] = "schedule_cpu, current_duration_time %llu, "
                               "last_duration_time %llu, duration_time %llu\n";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), now - *start_idle_time,
                         *value, duration_time);
      }
      bpf_map_update_elem(&idle_duration_time_map, &cpu, &duration_time,
                          BPF_EXIST);
    } else {
      bpf_map_update_elem(&idle_duration_time_map, &cpu, &duration_time,
                          BPF_NOEXIST);
    }
  }
  return 0;
}
