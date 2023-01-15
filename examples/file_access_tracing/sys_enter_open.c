// +build ignore

#include "bpf_tracing.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16

struct event {
  u32 syscall_nr;
  u8 filename[400];
  u32 flags;
  u32 mode;
  int pid;
  char comm[TASK_COMM_LEN];
  int ppid;
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

/*int endWith(char *originString, char *end) {
  if (originString == NULL || end == NULL ||
      strlen(end) > strlen(originString)) {
    return -1;
  }
  int n = strlen(end);
  int m = strlen(originString);
  int i;
  for (i = 0; i < n; i++) {
    if (originString[m - i - 1] != end[n - i - 1]) {
      return 1;
    }
  }
  return 0;
}*/

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_open(struct syscalls_enter_openat_args *ctx) {
  char *fname = (char *)(ctx->filename_ptr);
  struct event event;
  event.syscall_nr = ctx->syscall_nr;
  event.flags = ctx->flags;
  event.mode = ctx->mode;
  bpf_probe_read_str(&event.filename, sizeof(event.filename), fname);

  event.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&event.comm, TASK_COMM_LEN);
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task != NULL) {
    event.ppid = task->real_parent->tgid
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}
