#include "hello_world.skel.h"
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <poll.h>

static __u32 xdp_flags = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {

  struct hello_world_bpf *skel;
  int err = 0;

  char *ifname;

  // Check if the interface name is provided as a command-line argument
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <interface-name>\n", argv[0]);
    return -1;
  }

  ifname = argv[1];

  // redirect libbpf errs to stdout
  libbpf_set_print(libbpf_print_fn);

  // open the .o file
  skel = hello_world_bpf__open();

  // Set program type to XDP
  bpf_program__set_type(skel->progs.xdp_dad, BPF_PROG_TYPE_XDP);

  // Get the interface index of the desired interface (e.g., ens3)
  int ifindex = if_nametoindex(ifname);
  if (ifindex == 0) {
    perror("if_nametoindex");
    goto cleanup;
  }

  // load xdp
  err = hello_world_bpf__load(skel);
  if (err) {
    printf("Error while loading BPF skeleton");
    goto cleanup;
  }

  xdp_flags = 0;
  xdp_flags |= XDP_FLAGS_DRV_MODE;
  xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

  // attach prog
  err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_dad), xdp_flags, NULL);
  if (err) {
    printf("Error while attaching BPF skeleton");
    goto cleanup;
  }

  printf("Successfully attached!\n\n");

  // loop until char c is received
  char input;
  int exit_flag = 0;
  struct pollfd mypoll = { STDIN_FILENO, POLLIN|POLLPRI };

  printf("Type 'q' to exit...\n");
  while (!exit_flag) {

    // Check if there's input available
    if( poll(&mypoll, 1, 2000) )
    {
      scanf("%c", &input);
      if (input == 'q') {
        exit_flag = 1; // Set flag to exit the loop
      }
    }

    //sleep(1);
  }
  printf("Bye\n");

detach:
  // detach prog
  err = bpf_xdp_detach(ifindex, xdp_flags, NULL);
  if (err) {
    printf("Error while detaching XDP from interface");
  }

cleanup:
  hello_world_bpf__destroy(skel);

  return -err;
}
