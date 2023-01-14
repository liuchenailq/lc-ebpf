// +build ignore

#include "common.h"
#include <sys/types.h>
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
  int syscall_nr;
  u8 filename [1024];
  int flags;
  mode_t mode;
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

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscalls_enter_open_args *ctx) {
    struct event *e;
    char *fname = (char *)(ctx->filename_ptr);
    e->syscall_nr = ctx->syscall_nr;
    e->flags = ctx->flags;
    e->mode = ctx->mode;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), fname);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
