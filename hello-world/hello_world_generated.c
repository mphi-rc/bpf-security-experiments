#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <stdlib.h>

#define BPF_INSN(OPCODE, DESTINATION, SOURCE, OFFSET, IMMEDIATE) \
  ((struct bpf_insn){.code = OPCODE,                             \
                     .dst_reg = DESTINATION,                     \
                     .src_reg = SOURCE,                          \
                     .off = OFFSET,                              \
                     .imm = IMMEDIATE})

union bpf_attr* prog_tracepoint_hello_world(int fd_example, char* license,
                                            char* log_buf, int log_buf_size,
                                            int log_level) {
  struct bpf_insn* program = calloc(32, sizeof(struct bpf_insn));
  program[0] = BPF_INSN(0x85, 0, 0, 0, 14);
  program[1] = BPF_INSN(0x7b, 10, 0, -8, 0);
  program[2] = BPF_INSN(0xbf, 6, 10, 0, 0);
  program[3] = BPF_INSN(0x07, 6, 0, 0, -8);
  program[4] = BPF_INSN(0x18, 1, 1, 0, fd_example);
  program[5] = BPF_INSN(0x00, 0, 0, 0, 0);
  program[6] = BPF_INSN(0xbf, 2, 6, 0, 0);
  program[7] = BPF_INSN(0xbf, 3, 6, 0, 0);
  program[8] = BPF_INSN(0xb7, 4, 0, 0, 0);
  program[9] = BPF_INSN(0x85, 0, 0, 0, 2);
  program[10] = BPF_INSN(0x18, 1, 1, 0, fd_example);
  program[11] = BPF_INSN(0x00, 0, 0, 0, 0);
  program[12] = BPF_INSN(0xbf, 2, 6, 0, 0);
  program[13] = BPF_INSN(0x85, 0, 0, 0, 1);
  program[14] = BPF_INSN(0x15, 0, 0, 15, 0);
  program[15] = BPF_INSN(0xb7, 1, 0, 0, 10);
  program[16] = BPF_INSN(0x6b, 10, 1, -12, 0);
  program[17] = BPF_INSN(0xb7, 1, 0, 0, 1970021664);
  program[18] = BPF_INSN(0x63, 10, 1, -16, 0);
  program[19] = BPF_INSN(0x18, 1, 0, 0, 1948282223);
  program[20] = BPF_INSN(0x00, 0, 0, 0, 1025533033);
  program[21] = BPF_INSN(0x7b, 10, 1, -24, 0);
  program[22] = BPF_INSN(0x18, 1, 0, 0, 1819043176);
  program[23] = BPF_INSN(0x00, 0, 0, 0, 1919295599);
  program[24] = BPF_INSN(0x7b, 10, 1, -32, 0);
  program[25] = BPF_INSN(0x79, 3, 0, 0, 0);
  program[26] = BPF_INSN(0xbf, 1, 10, 0, 0);
  program[27] = BPF_INSN(0x07, 1, 0, 0, -32);
  program[28] = BPF_INSN(0xb7, 2, 0, 0, 22);
  program[29] = BPF_INSN(0x85, 0, 0, 0, 6);
  program[30] = BPF_INSN(0xb7, 0, 0, 0, 0);
  program[31] = BPF_INSN(0x95, 0, 0, 0, 0);
  union bpf_attr* ret = calloc(1, sizeof(union bpf_attr));
  ret->prog_type = BPF_PROG_TYPE_KPROBE;
  ret->insns = (unsigned long)program;
  ret->insn_cnt = 32;
  ret->log_buf = (unsigned long)log_buf;
  ret->log_size = log_buf_size;
  ret->log_level = log_level;
  ret->license = (unsigned long)license;
  return ret;
}

union bpf_attr map_example = {
    .map_type = 1,
    .key_size = 8,
    .value_size = 8,
    .max_entries = 10240,
    .map_flags = 0,
};
