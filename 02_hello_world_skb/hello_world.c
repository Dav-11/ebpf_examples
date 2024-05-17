
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello_world.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG) return 0;

  return vfprintf(stderr, format, args);
}

int main() {
  struct hello_world_bpf *skel;
  int err;

  // redirect libbpf errs to stdout
  libbpf_set_print(libbpf_print_fn);

  // open the .o file
  skel = hello_world_bpf__open();

  /* space to init maps values */

  // load prog inside kernel
  hello_world_bpf__load(skel);

  // attach prog
  err = hello_world_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto destroy_prog;
  }

  // loop until char c is received
  printf("Type 'c' to exit...\n");
  while (getchar() != 'c') {
    sleep(1);
  }
  printf("Bye\n");

destroy_prog:
  hello_world_bpf__destroy(skel);

  return -err;
}