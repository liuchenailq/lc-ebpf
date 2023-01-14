// +build ignore

#include "bpf_tracing.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
  u32 syscall_nr;
  u8 filename[400];
  u32 flags;
  u32 mode;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct syscalls_enter_open_args {
  /* The first 8 bytes is not allowed to read */
  unsigned long pad;

  long long syscall_nr;
  long long filename_ptr;
  long long flags;
  long long mode;
};

struct syscalls_enter_openat_args {
  /* The first 8 bytes is not allowed to read */
  unsigned long pad;

  long long syscall_nr;
  long long dfd;
  long long filename_ptr;
  long long flags;
  long long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_open(struct syscalls_enter_openat_args *ctx) {
  struct event event;
  char *fname = (char *)(ctx->filename_ptr);
  event.syscall_nr = ctx->syscall_nr;
  event.flags = ctx->flags;
  event.mode = ctx->mode;
  bpf_probe_read_str(&event.filename, sizeof(event.filename), fname);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}
