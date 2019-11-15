#!/usr/bin/env bash

name="log_pages"
kernel_header_path="/usr/src/linux-headers-$(uname -r)"

function compile_bpf() {
  clang-9 -D __KERNEL__ -O3 -I "${kernel_header_path}/include/" -I "${kernel_header_path}/arch/x86/include/" \
    -emit-llvm -c "${name}_kernel.c" -o - | llc-9 -march=bpf -filetype=obj -o "${name}_kernel.o"
}

function compile_code_generator() {
  gcc ../generate.c -o ../generate
}

function generate_c_bpf() {
  ../generate "${name}_kernel.o" > "${name}_generated.c"
}

function compile_userspace() {
  gcc "${name}_user.c" -o "${name}_user"
}

function fail() {
  >&2 echo "$1"; exit 1
}

compile_bpf || \
  fail "Unable to compile BPF program. Ensure clang-9 and llc-9 are installed, and kernel headers are available."
compile_code_generator || \
  fail "Unable to compile C code generator tool. Ensure gcc is installed."
generate_c_bpf || \
  fail "Code generation failed."
compile_userspace || \
  fail "Unable to compile userspace BPF program loader. Ensure gcc is installed."
