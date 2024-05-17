#ifndef __XDP_DAD_H__
#define __XDP_DAD_H__

#define MAX_ENTRY 3
#define ETH_ALEN 6

struct arp_entry {
  unsigned char mac[MAX_ENTRY][ETH_ALEN];
  int size;
};

#endif /*__XDP_DAD_H__*/