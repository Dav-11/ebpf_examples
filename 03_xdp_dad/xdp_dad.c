#include "xdp_dad.h"
#include "xdp_dad.skel.h"
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

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
  struct arp_entry *entry;
  char ip_str[20];

  printf("arp entries:\n");

  // Iterate through all the keys in the map
  while (bpf_map__get_next_key(skel->maps.xdp_stats_map, &key, &next_key,
                               sizeof(key)) == 0) {

    // Lookup the map entry by the current key
    int res =
        bpf_map__lookup_elem(skel->maps.xdp_stats_map, &next_key, sizeof(__u32),
                             &entry, sizeof(entry), BPF_ANY);
    if (res == 0) {

      // Convert the key (IP address) to a human-readable string
      if (inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str)) == NULL) {

        perror("inet_ntop");
        continue;
      }

      // Print the IP address
      printf("IP address: %s\n", ip_str);

      // Process the entry (for example, print MAC addresses)
      for (int i = 0; i < entry->size; i++) {
        printf("\t\tMAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               entry->mac[i][0], entry->mac[i][1], entry->mac[i][2],
               entry->mac[i][3], entry->mac[i][4], entry->mac[i][5]);
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

  // load xdp
  err = xdp_dad_bpf__load(skel);
  if (err) {
    printf("Error while loading BPF skeleton");
    goto cleanup;
  }

  // attach prog
  err = xdp_dad_bpf__attach(skel);
  if (err) {
    printf("Error while attaching BPF skeleton");
    goto cleanup;
  }

  printf("Successfully attached!\n\n");

  // loop until char c is received

  printf("Type 'c' to exit...\n");
  while (getchar() != 'c') {

    if (print_map_data(skel) < 0) {
      printf("Error while printing map data");
      goto cleanup;
    }

    sleep(1);
  }
  printf("Bye\n");

cleanup:
  xdp_dad_bpf__destroy(skel);

  return -err;
}