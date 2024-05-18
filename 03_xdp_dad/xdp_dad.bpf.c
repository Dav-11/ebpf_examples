#include "xdp_dad.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#define ETH_P_ARP 0x0806

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32); // ip of source
  __type(value, struct arp_entry);
  __uint(max_entries, 1024);
} xdp_stats_map SEC(".maps");

struct data_t {
  void *data_end;
  void *data;
  void *pos;
};

struct arp_hdr {
  __be16 htype;       // Hardware Type
  __be16 ptype;       // Protocol Type
  __u8 hlen;          // Hardware Address Length
  __u8 plen;          // Protocol Address Length
  __be16 oper;        // Operation
  __u8 sha[ETH_ALEN]; // Sender Hardware Address (MAC)
  __be32 spa;         // Sender Protocol Address (IP)
  __u8 tha[ETH_ALEN]; // Target Hardware Address (MAC)
  __be32 tpa;         // Target Protocol Address (IP)
};

static __always_inline struct ethhdr *get_ethhdr_arp(struct data_t *data) {

  if (data->pos + sizeof(struct ethhdr) > data->data_end) {
    return NULL;
  }

  struct ethhdr *eth = data->pos;

  // increment position to next header
  data->pos += sizeof(struct ethhdr);

  // check if pkg is arp
  if (eth->h_proto != bpf_htons(ETH_P_ARP)) {
    return NULL;
  }

  return eth;
}

static __always_inline struct arp_hdr *get_arphdr(struct data_t *data) {

  if (data->pos + sizeof(struct arp_hdr) > data->data_end) {
    return NULL;
  }

  struct arp_hdr *arp = data->pos;

  // increment position to next header
  data->pos += sizeof(struct arp_hdr);

  return arp;
}

static __always_inline void print_ip (__u32 ip) {
  bpf_printk("IP: %x\n", ip);
}

SEC("xdp")
int xdp_dad(struct xdp_md *ctx) {

  struct data_t data;
  data.data = (void *)(long)ctx->data;
  data.data_end = (void *)(long)ctx->data_end;
  data.pos = data.data;

  struct ethhdr *eth;
  struct arp_hdr *arp;

  // get the ethernet header
  eth = get_ethhdr_arp(&data);
  if (!eth) {
    return XDP_PASS;
  }

  arp = get_arphdr(&data);
  if (!arp) {
    return XDP_PASS;
  }

  bpf_printk("[xdp_dad]: [TYPE:%u] ", bpf_ntohs(arp->oper));

  // Check if this is an ARP response (opcode 2)
  if (bpf_ntohs(arp->oper) != 2u) {
    return XDP_PASS;
  }

  bpf_printk("[RESPONSE] ");

  print_ip(arp->spa);

  // lookup ip address
  struct arp_entry *entry = bpf_map_lookup_elem(&xdp_stats_map, &arp->spa);
  if (!entry) {

    // create new entry
    struct arp_entry new_entry = {};

    // copy mac address
    memcpy(new_entry.mac[0], arp->sha, ETH_ALEN);

    // set size to 1
    new_entry.size = 1;

    // insert new entry
    int err = bpf_map_update_elem(&xdp_stats_map, &arp->spa, &new_entry, BPF_ANY);
    if (err) {
      bpf_printk("failed to insert entry: %d\n", err);
      return XDP_PASS;
    }

    bpf_printk("[NEW ENTRY ADDED FOR IP] ");

    return XDP_PASS;
  }

  if (ETH_ALEN != sizeof(arp->sha)) {
    return XDP_PASS;
  }

  memcpy(entry->mac[entry->size], arp->sha, ETH_ALEN);
  entry->size++;

  // update map
  int err = bpf_map_update_elem(&xdp_stats_map, &arp->spa, entry, BPF_ANY);
  if (err) {
    bpf_printk("failed to insert entry: %d\n", err);
    return XDP_PASS;
  }

  // Continue processing the packet as usual
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
