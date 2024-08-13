#include <stdio.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "xdp_drop_ipv4.skel.h"

static __u32 xdp_flags = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    if (level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {

    struct xdp_drop_ipv4_bpf *skel;
    int err = 0;

    char *ifname;

    // Check if the interface name is provided as a command-line argument
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface-name>\n", argv[0]);
        return -1;
    }

    ifname = argv[1];

    skel = xdp_drop_ipv4_bpf__open();

    // Set program type to XDP
    bpf_program__set_type(skel->progs.xdp_drop_ipv4, BPF_PROG_TYPE_XDP);

    // Get the interface index of the desired interface (e.g., ens3)
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        goto cleanup;
    }

    err = xdp_drop_ipv4_bpf__load(skel);
    if (err) {
        printf("Error while loading BPF skeleton");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;
    xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

    // attach prog
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_drop_ipv4), xdp_flags, NULL);
    if (err) {
        printf("Error while attaching BPF skeleton");
        goto cleanup;
    }

    printf("Successfully attached!\n\n");

cleanup:
    xdp_drop_ipv4_bpf__destroy(skel);

    return -err;

detach:
    // detach prog
    err = bpf_xdp_detach(ifindex, xdp_flags, NULL);
    if (err) {
        printf("Error while detaching XDP from interface");
    }
}
