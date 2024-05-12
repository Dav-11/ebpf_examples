
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

__u32 count = 0;

SEC("xdp")
int hello_world(struct xdp_md *ctx) {
  count++;
  bpf_printk("Hello World %d", count);

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";