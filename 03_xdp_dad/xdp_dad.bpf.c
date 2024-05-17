#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct arp_entry {
    __u64 rx_packets;
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
    if (data + sizeof(struct eth_hdr) > data_end) {
        return XDP_PASS;
    }

    struct eth_hdr *eth = data;

    // Check if this is an ARP packet
    if (bpf_ntohs(eth->eth_proto) != ETH_P_ARP) {
        return XDP_PASS;
    }

    // Check if we have at least the ARP header
    if (data + sizeof(struct eth_hdr) + ARP_HDR_LEN > data_end) {
        return XDP_PASS;
    }

    struct arp_hdr *arp = data + sizeof(struct eth_hdr);

    // Check if this is an ARP response (opcode 2)
    if (bpf_ntohs(arp->oper) != ARPOP_REPLY) {
        return XDP_PASS;
    }

    // Extract the MAC address and IP address from the ARP response
    bpf_printk("ARP Response: Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x, Sender IP: %d.%d.%d.%d\n",
               arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2], arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5],
               (arp->ar_sip >> 24) & 0xff, (arp->ar_sip >> 16) & 0xff, (arp->ar_sip >> 8) & 0xff, arp->ar_sip & 0xff
    );

    // Continue processing the packet as usual
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
