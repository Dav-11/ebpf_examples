#include "xdp_dad.h"
#include "xdp_dad.skel.h"
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

int print_map_data(struct xdp_dad_bpf *skel) {

  int xdp_stats_map_fd = bpf_map__fd(skel->maps.xdp_stats_map);

  // Check if the file descriptor is valid
  if (xdp_stats_map_fd < 0) {

    printf("Failed to get file descriptor of BPF map: %d\n", errno);
    return -1;
  }

  __u32 key = 0;
  __u32 next_key;
  struct arp_entry entry;
  char ip_str[20];

  printf("arp entries:\n");

  // Iterate through all the keys in the map
  while (bpf_map__get_next_key(skel->maps.xdp_stats_map, &key, &next_key,
                               sizeof(__u32)) == 0) {

    // Convert the key (IP address) to a human-readable string
    if (inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str)) == NULL) {

      perror("inet_ntop");
      continue;
    }

    printf("\t[IP: %s]\n", ip_str);

    // Lookup the map entry by the current key
    int res =
        bpf_map__lookup_elem(skel->maps.xdp_stats_map, &next_key, sizeof(__u32),
                             &entry, sizeof(struct arp_entry), BPF_ANY);
    if (res == 0) {

      // Process the entry (for example, print MAC addresses)
      for (int i = 0; i < entry.size; i++) {
        printf("\t\t\t[%d] [MAC: %02x:%02x:%02x:%02x:%02x:%02x]\n", i,
               entry.mac[i][0], entry.mac[i][1], entry.mac[i][2],
               entry.mac[i][3], entry.mac[i][4], entry.mac[i][5]);
      }
    }
    // Update key to next_key for the next iteration
    key = next_key;
  }

  return 0;
}

int main() {

  struct xdp_dad_bpf *skel;
  int err = 0;

  // redirect libbpf errs to stdout
  libbpf_set_print(libbpf_print_fn);

  // open the .o file
  skel = xdp_dad_bpf__open();

  // Set program type to XDP
  bpf_program__set_type(skel->progs.xdp_dad, BPF_PROG_TYPE_XDP);

  // Get the interface index of the desired interface (e.g., ens3)
  int ifindex = if_nametoindex("ens3");
  if (ifindex == 0) {
    perror("if_nametoindex");
    goto cleanup;
  }

  // load xdp
  err = xdp_dad_bpf__load(skel);
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

    if (print_map_data(skel) < 0) {
      printf("Error while printing map data");
      goto detach;
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
  xdp_dad_bpf__destroy(skel);

  return -err;
}