#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#define ETH_P_ARP 0x0806
#define ETH_ALEN 6

#define MAX_ENTRY 3

struct arp_entry {
  unsigned char mac[MAX_ENTRY][ETH_ALEN];
  int size;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32); // ip of source
  __type(value, struct arp_entry);
  __uint(max_entries, 1024);
} xdp_stats_map SEC(".maps");

__u32 count = 0;

SEC("xdp")
int xdp_dad(struct xdp_md *ctx) {

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Check if we have at least the Ethernet header
  if (data + sizeof(struct ethhdr) > data_end) {
    return XDP_PASS;
  }

  struct ethhdr *eth = data;

  // Check if this is an ARP packet
  if (bpf_ntohs(eth->h_proto) != ETH_P_ARP) {
    return XDP_PASS;
  }

  // Check if we have at least the ARP header
  if (data + sizeof(struct ethhdr) + sizeof(struct arphdr) > data_end) {
    return XDP_PASS;
  }

  struct arphdr *arp = data + sizeof(struct ethhdr);

  // Check if this is an ARP response (opcode 2)
  if (bpf_ntohs(arp->ar_op) != 2) {
    return XDP_PASS;
  }

  if (data + sizeof(struct ethhdr) + sizeof(struct arphdr) + ETH_ALEN + 4 >
      data_end) {
    return XDP_PASS;
  }

  unsigned char *mac = data + sizeof(struct ethhdr) + sizeof(struct arphdr);
  __u32 ip =
      (__u32)data + sizeof(struct ethhdr) + sizeof(struct arphdr) + ETH_ALEN;

  // lookup ip address
  struct arp_entry *entry = bpf_map_lookup_elem(&xdp_stats_map, &ip);
  if (!entry) {

    // create new entry
    struct arp_entry new_entry;

    // copy mac-address into first array elem
    memcpy(new_entry.mac[0], mac, ETH_ALEN);

    // set size to 1
    new_entry.size = 1;

    // insert new entry
    bpf_map_update_elem(&xdp_stats_map, &ip, &new_entry, BPF_ANY);

    return XDP_PASS;
  }

  memcpy(entry->mac[entry->size], mac, ETH_ALEN);
  entry->size++;

  // update map
  bpf_map_update_elem(&xdp_stats_map, &ip, entry, BPF_ANY);

  // Continue processing the packet as usual
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
