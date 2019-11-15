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

#define SWAP(x)                                                \
  (x & 0xff) << 24 | (x & 0xff00) << 8 | (x & 0xff0000) >> 8 | \
      (x & 0xff000000) >> 24
#define TYPE_X25519 1034

/* The following typedefs are taken directly from OpenSSL source code. */
typedef _Atomic int CRYPTO_REF_COUNT;
typedef struct evp_pkey_st EVP_PKEY;

typedef struct ecx_key_st ECX_KEY;

struct ecx_key_st {
  unsigned char pubkey[57];
  unsigned char *privkey;
};

struct evp_pkey_st {
  int type;
  int save_type;
  CRYPTO_REF_COUNT references;
  void *ameth;
  void *engine;
  void *pmeth_engine;
  union {
    void *ptr;
    struct rsa_st *rsa;   /* RSA */
    struct dsa_st *dsa;   /* DSA */
    struct dh_st *dh;     /* DH */
    struct ec_key_st *ec; /* ECC */
    ECX_KEY *ecx;         /* X25519, X448, Ed25519, Ed448 */
  } pkey;
  int save_parameters;
};

__attribute__((section("maps"))) struct bpf_map_def pkey_addr_by_tid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(EVP_PKEY **),
    .max_entries = 10240,
};

__attribute__((section("tracepoint/save_pkey_addr"))) int save_pkey_addr(
    struct pt_regs *ctx) {
  /* The OpenSSL function we are hooking populates a parameter, then returns.
   * This poses a problem because if we create a only uprobe, the parameter will
   * not yet be populated, and if we create only a uretprobe we won't be able to
   * reference a parameter.
   *
   * To solve this, we'll have to create both a uprobe and a uretprobe. In our
   * uprobe BPF program, we'll store the memory address of the parameter we care
   * about, in a BPF map. In our uretprobe, we'll retrieve it and inspect the
   * stored value. */

  /* This macro converts a refers to our CPU register state to a reference to
   * the second function parameter. Note that calling conventions are
   * architecture specific, so it'll be different if you're not on x86-64. */
  EVP_PKEY **pkey_addr = (EVP_PKEY **)PT_REGS_PARM2(ctx);

  /* We'll key our BPF map by process ID and thread ID, which should be unique
   * enough. */
  __u64 tid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&pkey_addr_by_tid, &tid, &pkey_addr, BPF_ANY);
  return 0;
}

__attribute__((section("tracepoint/read_pkey"))) int read_pkey(
    struct pt_regs *ctx) {
  /* Let's read the address of our saved key parameter, then remove it from the
   * map. */
  __u64 tid = bpf_get_current_pid_tgid();
  EVP_PKEY ***pkey_addr = bpf_map_lookup_elem(&pkey_addr_by_tid, &tid);
  if (pkey_addr == NULL) {
    return 0;
  }
  bpf_map_delete_elem(&pkey_addr_by_tid, &tid);

  /* Reading memory outside of the BPF stack must go through bpf_probe_read().
   * This helps the BPF verifier determine whether the program is memory safe.
   */
  EVP_PKEY *p;
  bpf_probe_read(&p, sizeof(EVP_PKEY *), *pkey_addr);

  /* For TLS 1.3, we only care about X25519 ephemeral keys. */
  int type;
  bpf_probe_read(&type, sizeof(int), &(p->type));
  if (type == TYPE_X25519) {
    ECX_KEY *key;
    bpf_probe_read(&key, sizeof(ECX_KEY *), &(p->pkey.ecx));

    /* Remember, we can't loop in a BPF program, so our code is going to be a
     * little more verbose than we're used to. */
    __u64 k;
    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)&key->pubkey) + 0);
    /* The BPF printk function writes to /sys/kernel/debug/tracing/trace_pipe.
     * Note that it doesn't support printing 64-bit hex values, so we'll print
     * two 32-bit ones.
     *
     * We'll also use the SWAP macro (defined above) to reverse the order from
     * big endian (aka network byte order) to little endian (for our x86-64
     * architecture). */
    printk("%u X25519 pub 0: %x %x\n", tid, SWAP(k), SWAP(k >> 32));
    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)&key->pubkey) + 1);
    printk("%u X25519 pub 1: %x %x\n", tid, SWAP(k), SWAP(k >> 32));
    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)&key->pubkey) + 2);
    printk("%u X25519 pub 2: %x %x\n", tid, SWAP(k), SWAP(k >> 32));
    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)&key->pubkey) + 3);
    printk("%u X25519 pub 3: %x %x\n", tid, SWAP(k), SWAP(k >> 32));

    __u64 *privkey;
    bpf_probe_read(&privkey, sizeof(char *), &(key->privkey));

    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)privkey) + 0);
    printk("%u X25519 prv 0: %x %x\n", tid, SWAP(k), SWAP(k >> 32));
    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)privkey) + 1);
    printk("%u X25519 prv 1: %x %x\n", tid, SWAP(k), SWAP(k >> 32));
    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)privkey) + 2);
    printk("%u X25519 prv 2: %x %x\n", tid, SWAP(k), SWAP(k >> 32));
    bpf_probe_read(&k, sizeof(__u64), ((__u64 *)privkey) + 3);
    printk("%u X25519 prv 3: %x %x\n", tid, SWAP(k), SWAP(k >> 32));
  }
  return 0;
}

__attribute__((section("license"))) char _license[] = "GPL";
