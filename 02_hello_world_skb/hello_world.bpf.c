
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

__u32 count = 0;

SEC("sk_skb/prog_parser")
int hello_world_skb(struct __sk_buff *skb) {
  count++;
  bpf_printk("Hello World %d", count);

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";