// +build ignore

#include "bpf_tracing.h"
#include "common.h"
#include <linux/sched.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
  u32 syscall_nr;
  u8 filename[100];
  u32 flags;
  u32 mode;
  u32 pid;
  u8 c_comm[16];
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

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscalls_enter_open_args *ctx) {
  char *fname = (char *)(ctx->filename_ptr);
  struct event event;
  bpf_probe_read_str(&event.filename, sizeof(event.filename), fname);
  if ((event.filename[0] == '/' && event.filename[1] == 'o' &&
       event.filename[2] == 'p' && event.filename[3] == 't' &&
       event.filename[4] == '/' && event.filename[5] == 'n' &&
       event.filename[6] == 'c' && event.filename[7] == 'i' &&
       event.filename[8] == 'n' && event.filename[9] == 'f' &&
       event.filename[10] == 'o') ||
      (event.filename[0] == 'l' && event.filename[1] == 'o' &&
       event.filename[2] == 'c' && event.filename[3] == 'a' &&
       event.filename[4] == 'l' && event.filename[5] == '_' &&
       event.filename[6] == 'm' && event.filename[7] == 'a' &&
       event.filename[8] == 'c' && event.filename[9] == 'h' &&
       event.filename[10] == 'i' && event.filename[11] == 'n' &&
       event.filename[12] == 'e' && event.filename[13] == '_' &&
       event.filename[14] == 'i' && event.filename[15] == 'n' &&
       event.filename[16] == 'f' && event.filename[17] == 'o') || (event.filename[16] == 'n' && event.filename[17] == 'c' && event.filename[18] == '_'
        && event.filename[19] == 'r' && event.filename[20] == 'e' && event.filename[21] == 's' && event.filename[22] == 'o' && event.filename[23] == 'u'
        && event.filename[24] == 'r' && event.filename[25] == 'c' && event.filename[26] == 'e' && event.filename[27] == 's' && event.filename[28] == '.'
        && event.filename[29] == 'c' && event.filename[30 == 'o' && event.filename[31] == 'n' && event.filename[32] == 'f'
        ) ||
        (event.filename[16] == 'r' && event.filename[17] == 'e' && event.filename[18] == 's'
                 && event.filename[19] == 'o' && event.filename[20] == 'u' && event.filename[21] == 'r' && event.filename[22] == 'c' && event.filename[23] == 'e'
                 && event.filename[24] == 's' && event.filename[25] == '.' && event.filename[26] == 'y' && event.filename[27] == 'a' && event.filename[28] == 'm'
                                                                                                                                             && event.filename[29] == 'l')
        ) {





    event.syscall_nr = ctx->syscall_nr;
    event.flags = ctx->flags;
    event.mode = ctx->mode;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.c_comm, 16);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));
    // get ppid
    // struct task_struct *task;
    // struct task_struct *parent;
    // task = (struct task_struct *)bpf_get_current_task();
    // bpf_probe_read(&event.ppid, sizeof(event.ppid), (void *)task);
    // event.ppid = task->real_parent->tgid;
    /*if (task != NULL) {
      bpf_probe_read_kernel(parent, sizeof(parent), task->real_parent);
      if (parent != NULL) {
        bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent->tgid);
      }
    }*/
    return 0;
  }
  return -1;
}
