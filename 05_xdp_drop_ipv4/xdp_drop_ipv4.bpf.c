#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>


//#include <linux/bpf.h>

#define ETH_P_IP	0x0800

struct data_t {
    void *data_end;
    void *data;
    void *pos;
};


SEC("xdp")
int xdp_drop_ipv4(struct xdp_md *ctx)
{
    struct data_t data;
    data.data = (void *)(long)ctx->data;
    data.data_end = (void *)(long)ctx->data_end;
    data.pos = data.data;

    if (data.pos + sizeof(struct ethhdr) > data.data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data.pos;
    data.pos += sizeof(struct ethhdr);

    // Check if packet is IP
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
