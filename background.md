# Dynamic binary instrumentation with BPF

BPF programs are fast becoming the de facto standard for integrating with, and extending, the feature set of the Linux 
kernel. Areas such as networking and performance tracing have found huge utility in BPF, but we haven't seen much 
adoption for security use cases.

This repo documents my experiments in writing BPF and interfacing with Linux kernel syscalls from scratch, as well as 
a few proof-of-concept security monitoring programs that use BPF for dynamic binary instrumentation. One example logs 
HTTP(S) URLs loaded by Firefox, and another logs TLS 1.3 ephemeral keypairs created by OpenSSL.

I spent time getting acquainted with the BPF-wrapping library BCC, but was a little mystified about how it actually 
worked. I decided to write a "zero-dependency" BPF userspace program that interfaced directly with the kernel, and 
a basic BPF to C code generator.

## What's BPF and why has it become popular?

To integrate with the kernel before BPF, we'd have to write a kernel module, which is not an endeavor for the faint 
of heart. We'd likely write C, play a high-stakes game of memory safety (where a segfault manifests as a kernel 
panic), and then we'd be wedded to building our module for every kernel release.

BPF lets us do things a little differently. It's an instruction set that provides abstraction from the kernel binary 
interface and independence from kernel versioning. That allows us to write our BPF program once, build our binary and 
free ourselves from the ball and chain of kernel version compatibility.

The Linux kernel implements a BPF virtual machine and runtime that provide strong guarantees: a BPF program can't 
make unsafe memory accesses and is guaranteed to terminate. Unlike a C kernel module, the BPF runtime prevents memory 
safety issues through static analysis at runtime. That means no more kernel panics for off-by-one errors during 
development.

But the kernel BPF verifier goes even further, enforcing hard limits on BPF stack memory usage (512k) and program 
length (4096 instructions, plus a monotonically increasing program counter). While this may seem a overbearing, it 
guarantees an upper bound on the cost of a BPF program.

Limiting resources so drastically lays the foundation for running BPF programs in performance-critical kernel code 
paths, with minimal impact to overall system performance. Ever wanted to instrument every system call in production? 
Now you can, and without significant cost.

BPF programs differ from standard kernel modules in another key way: there are categories of BPF program, each with a 
specialized purpose and limited scope. A BPF program that filters network packets is entirely different to a BPF 
program that inspects the parameters of a system call.

That extra context affords us a more nuanced approach to privilege levels. Previously, we could see a clear 
distinction between userspace — for our unprivileged, untrusted code — and kernel space — for our privileged OS 
code. With BPF, we can choose to grant userspace processes permission to create and execute classes of BPF programs in 
kernel space, without giving away total system access.

## BPF for security monitoring

Let's, for a second, imagine the most extreme form of system monitoring possible. Imagine being able to inspect 
every instruction executed on the CPU, as well as the state of the registers, stack, and heap memory.

While this is pretty extreme, it sounds a lot like running code in a debugger, albeit system-wide. Debuggers can 
trivially insert breakpoint instructions, and allow you to inspect program state, after the OS transfers execution to 
a debugger-controlled interrupt handler.

It might surprise you to learn that this exact functionality already exists within the Linux kernel tracing subsystem, 
with APIs available from userspace. Application developers can register so-called "probe points" (aka probes) at 
arbitrary kernel and userspace program addresses. And, as of kernel version 4.1, BPF programs can be attached to 
probes.

If we probe the start of a function — and we know the calling convention used — we can inspect the arguments 
passed to the function. Similarly, if we instrument the last instruction of a function, we can inspect its return 
value. We can do this *anywhere* — within the kernel, at the system call boundary, or within userspace binaries.

## Userspace binary instrumentation

Now this is where things get hairy. Let's walk through the steps required to instrument a function in a userspace 
binary. If you prefer to read code, check out the source code in this repo.

To register a userspace probe we need to reference the instruction to instrument by its offset into the target binary. 
We also need to specify whether this is the last instruction of the function, making our probe a userspace *return* 
probe ("uretprobe") or the first instruction of the function, making our probe a regular userspace probe 
("uprobe").

Identifying function offsets is easy when binaries have not been stripped of their symbols, but nigh-on impossible for 
compiler-inlined functions. Luckily, most userspace programs are not statically compiled, so shared libraries can be a 
treasure trove of opportunity for instrumentation. Let's make things easy and instrument a function in a shared 
library.

We can read the information we need from the symbol table of an ELF binary using readelf. If a symbol is of type 
function and has a non-zero value, this is its offset into the program binary. We can see some of the functions we 
could instrument in OpenSSL below:

```
ubuntu@server:~$ readelf -s /usr/lib/x86_64-linux-gnu/libssl.so.1.1 | tail
   946: 0000000000035920    72 FUNC    GLOBAL DEFAULT   13 SSL_set0_wbio@@OPENSSL_1_1_0
   947: 0000000000039620     8 FUNC    GLOBAL DEFAULT   13 SSL_CTX_get_record_paddin@@OPENSSL_1_1_1
   948: 0000000000047d40    39 FUNC    GLOBAL DEFAULT   13 SSL_CTX_add_custom_ext@@OPENSSL_1_1_1
   949: 00000000000380e0     8 FUNC    GLOBAL DEFAULT   13 SSL_get_default_passwd_cb@@OPENSSL_1_1_0
   950: 0000000000033940   261 FUNC    GLOBAL DEFAULT   13 SSL_CONF_CTX_finish@@OPENSSL_1_1_0
   951: 000000000003b710     5 FUNC    GLOBAL DEFAULT   13 SSL_alloc_buffers@@OPENSSL_1_1_1
   952: 000000000003d000   146 FUNC    GLOBAL DEFAULT   13 SSL_use_certificate@@OPENSSL_1_1_0
   953: 000000000003b400    18 FUNC    GLOBAL DEFAULT   13 SSL_client_hello_isv2@@OPENSSL_1_1_1
   954: 000000000002e660    55 FUNC    GLOBAL DEFAULT   13 SSL_get_ex_data_X509_STOR@@OPENSSL_1_1_0
   955: 00000000000323c0     4 FUNC    GLOBAL DEFAULT   13 SSL_CIPHER_get_id@@OPENSSL_1_1_0
```

Now we know how to reference our target function, we can work towards using the kernel APIs to attach a BPF program. 
In short, the process is:

1. load a BPF program from an array of bytecode, using the `bpf()` system call
2. register a new userspace probe with the tracing subsystem, by writing to `/sys/kernel/debug/tracing/uprobe_events`
3. open a new perf event, referencing our newly-created uprobe, using the `perf_event_open()` system call 
4. attach our loaded BPF program to our perf event, using the `ioctl()` system call
5. enable the perf event to enact the instrumentation, using the `ioctl()` system call

Once the perf event is enabled, the BPF program will run from the next execution of the userspace function. This 
happens totally transparently to every process that calls into our probed address, new or old, making our 
instrumentation truly dynamic.

However, we've skimmed over one very important detail: how to write a BPF program.

## BPF Compiler Collection

In practice, no one really writes BPF programs in raw bytecode, or calls the `bpf()` syscall directly, or manually 
provides references to offsets into target binaries. Instead, the BPF Compiler Collection (BCC) Python library has 
emerged as a popular way to write BPF programs, where all the details are handled for you.

BCC greatly simplifies writing BPF programs by allowing us to write in a restricted subset of C, and compile-down to 
BPF bytecode. This restricted subset has no backwards jumps and no function calls. So it's not easy to write, but 
it's a whole lot more pleasant than writing raw bytecode.

BCC also simplifies invoking BPF functions by providing convenient C macros. You can think of BPF functions like 
BPF-specific syscalls we call from within a BPF program. There's a `printf` equivalent, for example, and a ton of 
functions for pushing data back to userspace.

But BCC's benefits don't come for free — it isn't lightweight, and there's a lot of moving pieces that make 
reasoning about the execution of a BCC script non-trivial. More specifically, BCC requires a Python runtime, LLVM to 
compile the C-like program into BPF bytecode, and kernel sources — not just headers — for the helper functions.

What's more, is that these dependencies are required at *runtime*, which makes BCC less suited as a library for 
writing self-contained software that's more than just a wrapper around a BPF program. But, in fairness, it doesn't 
purport to be much more than that.

## Going it alone: avoiding BCC

It *is* possible to write software that uses BPF without BCC's slew of runtime dependencies, and without 
significantly compromising developer experience.

One of the most useful features of BCC is the ability to write C-like source and compile to BPF bytecode. That, 
strictly speaking, isn't a function of BCC but is a function of the LLVM compiler. To get the same benefit, we can 
use clang, the LLVM CLI front end, and use it only at compile-time.

Clang emits an ELF binary containing our BPF program, so we're going to have to do a little work to parse this 
binary and shape its contents into a `bpf()` syscall parameter. There are libraries out there that completely handle 
this process — so-called BPF loaders — but let's look at what we need to avoid this dependency.

## Generating C code from BPF bytecode

So what does a BPF loader do that we can't do? Surely, we just parse out the instructions from a function in our ELF 
binary and pass it to a syscall. Not so fast!

A BPF program that's moderately complex likely stores data off-stack or shares data with userspace, using BPF data 
structures known as maps. BPF programs reference maps using file descriptors, but these are allocated, at *runtime*, 
in userspace, from the process that loads the BPF program.

Now you might be asking yourself, how can our static BPF bytecode *possibly* reference file descriptor values 
allocated at runtime? Surely the kernel will reject BPF programs that attempt to use invalid file descriptors — and 
you'd be right. BPF loaders must dynamically rewrite instructions that reference BPF maps to reference valid file 
descriptors.

Luckily, the ELF file format has provision for encoding instruction relocation metadata known as "ELF 
relocations." LLVM uses these to make references to *logical* BPF maps. The upshot is that we must edit, or 
"relocate," BPF instructions to reference *physical* map descriptors at runtime, before we attempt to load our 
program through a `bpf()` syscall.

The lightweight code generator in this repo handles the process for us, enabling us to embed our BPF program directly 
in our C source and avoid a dependency on a BPF loader library. The code generator identifies references to maps in 
ELF relocations, and generates C code parameterized by map file descriptors. The generated code returns program and 
map structs that can be passed directly to the `bpf()` syscall.

Relying on the generated code means we need only to plumb the correct map file descriptor to the correct function 
parameter. Consequently we can build a single, zero-dependency, C binary that can run a BPF program that we wrote in a 
high level language.
