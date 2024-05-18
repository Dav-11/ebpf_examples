#include "xdp_dad.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#define ETH_P_ARP 0x0806
#define MAX_ENTRIES 1024

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32); // IP of source
  __type(value, struct arp_entry);
  __uint(max_entries, MAX_ENTRIES);
} xdp_stats_map SEC(".maps");

struct data_t {
  void *data_end;
  void *data;
  void *pos;
};

struct __attribute__((packed)) arp_hdr {
  __be16 htype; // Hardware Type
  __be16 ptype; // Protocol Type
  __u8 hlen;    // Hardware Address Length
  __u8 plen;    // Protocol Address Length
  __be16 oper;  // Operation
  __u8 sha[6];  // Sender Hardware Address (MAC)
  __be32 spa;   // Sender Protocol Address (IP)
  __u8 tha[6];  // Target Hardware Address (MAC)
  __be32 tpa;   // Target Protocol Address (IP)
};

struct ethhdr *get_ethhdr_arp(struct data_t *data) {

  if (data->pos + sizeof(struct ethhdr) > data->data_end) {
    return NULL;
  }

  struct ethhdr *eth = data->pos;

  // Increment position to next header
  data->pos += sizeof(struct ethhdr);

  // Check if packet is ARP
  if (bpf_ntohs(eth->h_proto) != ETH_P_ARP) {
    return NULL;
  }

  return eth;
}

static __always_inline struct arp_hdr *get_arphdr(struct data_t *data) {

  // bpf_printk("pkg size: [T: %d, R: %d] wanted: %u",
  //            (data->data_end - data->data), (data->data_end - data->pos),
  //            sizeof(struct arp_hdr));

  if (data->pos + sizeof(struct arp_hdr) > data->data_end) {
    return NULL;
  }

  struct arp_hdr *arp = data->pos;

  // Increment position to next header
  data->pos += sizeof(struct arp_hdr);

  return arp;
}

SEC("xdp")
int xdp_dad(struct xdp_md *ctx) {

  struct data_t data;
  data.data = (void *)(long)ctx->data;
  data.data_end = (void *)(long)ctx->data_end;
  data.pos = data.data;

  struct ethhdr *eth = get_ethhdr_arp(&data);
  if (!eth) {
    return XDP_PASS;
  }

  struct arp_hdr *arp = get_arphdr(&data);
  if (!arp) {

    bpf_printk("[xdp_dad]: failed to get arp header");
    return XDP_PASS;
  }

  bpf_printk("[xdp_dad]: [TYPE:%u] ", bpf_ntohs(arp->oper));

  // Check if this is an ARP response (opcode 2)
  if (bpf_ntohs(arp->oper) != 2u) {
    return XDP_PASS;
  }

  // Lookup IP address
  struct arp_entry *entry = bpf_map_lookup_elem(&xdp_stats_map, &arp->spa);
  if (!entry) {
    // Create new entry
    struct arp_entry new_entry = {};

    // Copy MAC address
    memcpy(new_entry.mac[0], arp->sha, ETH_ALEN);

    // Set size to 1
    new_entry.size = 1;

    // Insert new entry
    int err =
        bpf_map_update_elem(&xdp_stats_map, &arp->spa, &new_entry, BPF_ANY);
    if (err) {
      bpf_printk("failed to insert entry: %d\n", err);
      return XDP_PASS;
    }

    bpf_printk("[NEW ENTRY ADDED FOR IP: %x]", arp->spa);
    return XDP_PASS;
  }

  if (entry->size < 0 || entry->size >= MAX_ENTRY) {
    return XDP_PASS;
  }

  // check if already exists
  for (int i = 0; i < entry->size; i++) {
    if (memcmp(entry->mac[i], arp->sha, ETH_ALEN) == 0) {
      return XDP_PASS;
    }
  }

  memcpy(entry->mac[entry->size], arp->sha, ETH_ALEN);
  entry->size++;

  bpf_printk("[NEW ENTRY ADDED FOR IP: %x]", arp->spa);

  // Update map
  int err = bpf_map_update_elem(&xdp_stats_map, &arp->spa, entry, BPF_ANY);
  if (err) {
    bpf_printk("failed to update entry: %d\n", err);
    return XDP_PASS;
  }

  // Continue processing the packet as usual
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
