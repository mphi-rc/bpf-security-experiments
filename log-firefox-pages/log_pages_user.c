#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/perf_event.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "log_pages_generated.c"

#define PROBE_MAX_SIZE 4096
#define LOG_BUF_SIZE 102400

int attach_bpf_to_uprobe(bool is_retprobe, int program_fd, char* probe_name,
                         char* lib_path, unsigned long address) {
  char addr[19];
  snprintf(addr, sizeof(addr), "0x%lx", address);

  char probe[PROBE_MAX_SIZE];
  char probe_type = is_retprobe ? 'r' : 'p';
  int count = snprintf(probe, sizeof(probe), "%c:%s %s:%s", probe_type,
                       probe_name, lib_path, addr);

  int fp = open("/sys/kernel/debug/tracing/uprobe_events", O_WRONLY);
  if (fp == -1) {
    fprintf(
        stderr,
        "unable to open /sys/kernel/debug/tracing/uprobe_events for writing\n");
    if (errno == EINVAL) {
      fprintf(stderr, "your user does not appear to have write permission\n");
    } else if (errno == ENOENT) {
      fprintf(stderr,
              "the file does not exist -- your kernel may have been built "
              "without CONFIG_UPROBE_EVENTS=y?\n");
    }
    return errno;
  }
  ssize_t bytes_written = write(fp, &probe, strlen(probe));
  if (bytes_written != strlen(probe)) {
    fprintf(stderr, "unable to write a uprobe event (error code: %d)\n", errno);
    return 1;
  }
  int closed = close(fp);
  if (closed != 0) {
    fprintf(stderr, "unable to write a uprobe event (error code: %d)\n", errno);
    return errno;
  }

  char event_file_name[4096];
  snprintf(event_file_name, sizeof(event_file_name),
           "/sys/kernel/debug/tracing/events/uprobes/%s/id", probe_name);

  FILE* event = fopen(event_file_name, "r");
  if (event == NULL) {
    fprintf(stderr, "unable to read the ID of the uprobe tracepoint\n");
    return errno;
  }

  int tracepoint_id = -1;
  fscanf(event, "%d", &tracepoint_id);
  fclose(event);
  if (tracepoint_id == -1) {
    fprintf(stderr, "unable to read the ID of the uprobe tracepoint\n");
    return 1;
  }

  struct perf_event_attr perf_attr = {
      .size = sizeof(struct perf_event_attr),
      .type = PERF_TYPE_TRACEPOINT,
      .config = tracepoint_id,
  };

  int perf_fd =
      syscall(SYS_perf_event_open, &perf_attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);

  int io = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, program_fd);
  if (io == -1) {
    fprintf(stderr,
            "unable to attach the BPF program to the uprobe tracepoint (error "
            "code: %d)\n",
            errno);
    return errno;
  }

  io = ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
  if (io == -1) {
    fprintf(stderr, "failed to enable the uprobe tracepoint (error code: %d)\n",
            errno);
    return errno;
  }
  return 0;
}

int main() {
  char log_buf[LOG_BUF_SIZE];

  union bpf_attr* program_read_req =
      prog_tracepoint_read_req("GPL", NULL, 0, 0);
  int read_req_fd = syscall(__NR_bpf, BPF_PROG_LOAD, program_read_req,
                            sizeof(*program_read_req));
  if (read_req_fd == -1) {
    fprintf(stderr, "unable to load the BPF program (error code: %d)\n", errno);
    if (errno == ENOSPC) {
      printf(
          "the log buffer was too small for the output of the verifier; please "
          "try again with a larger buffer\n");
    } else if (errno == EACCES) {
      fprintf(stderr,
              "the program was rejected because it was deemed unsafe:\n");
      fprintf(stderr, "%s\n", log_buf);
    } else if (errno == EINVAL) {
      fprintf(stderr, "the program was invalid:\n");
      fprintf(stderr, "%s\n", log_buf);
    }
    return errno;
  }

  char* probe_name = "firefox_log_request";
  char* lib = "/usr/lib/firefox/libnspr4.so";
  unsigned long addr = 0xc560; // symbol "PR_Write"
  int ret = attach_bpf_to_uprobe(false, read_req_fd, probe_name, lib, addr);
  if (ret != 0) {
    return ret;
  }

  printf("blocking until user input...\n");
  getchar();

  return 0;
}
