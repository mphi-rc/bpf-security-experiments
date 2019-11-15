#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include "../bpf_helpers.h"

/* The BPF verifier really doesn't like string values in function arguments.
 * This macro ensures that it sees a fixed length, stack allocated character
 * array. */
#ifndef printk
#define printk(fmt, ...)                                       \
  ({                                                           \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })
#endif

/* Copied from libnss source. */
typedef enum PRDescType {
  PR_DESC_FILE = 1,
  PR_DESC_SOCKET_TCP = 2,
  PR_DESC_SOCKET_UDP = 3,
  PR_DESC_LAYERED = 4,
  PR_DESC_PIPE = 5
} PRDescType;

typedef struct PRIOMethods {
  PRDescType file_type;
} PRIOMethods;

typedef struct PRFileDesc {
  PRIOMethods *methods;
} PRFileDesc;

__attribute__((section("tracepoint/read_req"))) int read_req(
    struct pt_regs *ctx) {
  PRFileDesc fd;
  bpf_probe_read(&fd, sizeof(PRFileDesc), (void *)PT_REGS_PARM1(ctx));

  PRIOMethods methods;
  bpf_probe_read(&methods, sizeof(PRIOMethods), fd.methods);

  if (methods.file_type == 4) {
    __u32 amount = (__u32)PT_REGS_PARM3(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    char str[401] = {0};
    bpf_probe_read(str, amount > 400 ? 400 : amount, buf);
    if (str[0] == 'G' && str[1] == 'E' && str[2] == 'T') {
      int f1 = -1;
      int f2 = -1;
      int c = 0;
#pragma unroll
      for (int i = 0; i < 150; i++) {
        if (str[i] == '\r') {
          str[i] = 0;
          if (c == 0) {
            f1 = i;
            c++;
          } else {
            f2 = i;
            break;
          }
        }
      }
      printk("Request path: %s\n", str + 4);
      if (f2 != -1) {
        printk("Request host: %s\n", str + 8 + f1);
      }
    }
  }
  return 0;
}

__attribute__((section("license"))) char _license[] = "GPL";
