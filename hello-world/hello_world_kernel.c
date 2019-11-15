#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include "../bpf_helpers.h"

#ifndef printk
#define printk(fmt, ...)                                       \
  ({                                                           \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })
#endif

__attribute__((section("maps"))) struct bpf_map_def example = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 10240,
};

__attribute__((section("tracepoint/hello_world"))) int hello_world(
    struct pt_regs* ctx) {
  __u64 tid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&example, &tid, &tid, BPF_ANY);

  __u64* val = bpf_map_lookup_elem(&example, &tid);
  if (val == NULL) {
    return 0;
  }
  printk("hello from tid = %lu\n", *val);
  return 0;
}

__attribute__((section("license"))) char _license[] = "GPL";
