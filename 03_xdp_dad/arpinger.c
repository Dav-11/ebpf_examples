#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// Define the ARP header structure
struct arp_header {
  unsigned short int hardware_type;
  unsigned short int protocol_type;
  unsigned char hardware_len;
  unsigned char protocol_len;
  unsigned short int operation;
  unsigned char sender_mac[6];
  unsigned char sender_ip[4];
  unsigned char target_mac[6];
  unsigned char target_ip[4];
};

// Function to get the IP address of the local interface
void get_ip_address(const char *iface, struct in_addr *ip) {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

  if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
    perror("ioctl");
    close(fd);
    exit(EXIT_FAILURE);
  }

  *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

  close(fd);
}

// Function to get the MAC address of the local interface
void get_mac_address(const char *iface, unsigned char *mac) {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
    perror("ioctl");
    close(fd);
    exit(EXIT_FAILURE);
  }

  memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

  close(fd);
}

// Function to send an ARP request
void send_arp_request(int sockfd, struct sockaddr_ll *device,
                      struct in_addr *source_ip, unsigned char *source_mac,
                      struct in_addr *target_ip) {
  unsigned char buffer[42];
  struct ethhdr *eth = (struct ethhdr *)buffer;
  struct arp_header *arp = (struct arp_header *)(buffer + ETH_HLEN);

  // Construct Ethernet header
  memset(eth->h_dest, 0xff, 6);         // Destination MAC address (broadcast)
  memcpy(eth->h_source, source_mac, 6); // Source MAC address
  eth->h_proto = htons(ETH_P_ARP);

  // Construct ARP header
  arp->hardware_type = htons(1);
  arp->protocol_type = htons(ETH_P_IP);
  arp->hardware_len = 6;
  arp->protocol_len = 4;
  arp->operation = htons(ARPOP_REQUEST);
  memcpy(arp->sender_mac, source_mac, 6);
  memcpy(arp->sender_ip, source_ip, 4);
  memset(arp->target_mac, 0x00, 6);
  memcpy(arp->target_ip, target_ip, 4);

  // Send the packet
  if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)device,
             sizeof(*device)) <= 0) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[]) {
  int sockfd;
  struct sockaddr_ll device;
  struct ifreq ifr;
  struct in_addr ip_addr, subnet_mask, network_addr, broadcast_addr;
  unsigned char mac[6];
  char *iface;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  iface = argv[1];

  // Create raw socket
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // Get the MAC address of the interface
  get_mac_address(iface, mac);

  // Get the IP address of the interface
  get_ip_address(iface, &ip_addr);

  // Get the subnet mask of the interface
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) {
    perror("ioctl");
    close(sockfd);
    exit(EXIT_FAILURE);
  }
  subnet_mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

  // Calculate the network address
  network_addr.s_addr = ip_addr.s_addr & subnet_mask.s_addr;

  // Calculate the broadcast address
  broadcast_addr.s_addr = network_addr.s_addr | ~subnet_mask.s_addr;

  // Set up the sockaddr_ll structure
  memset(&device, 0, sizeof(device));
  device.sll_family = AF_PACKET;
  device.sll_ifindex = if_nametoindex(iface);
  device.sll_halen = htons(6);
  memset(device.sll_addr, 0xff, 6); // Broadcast address

  // Send ARP request for every IP in the subnet
  for (uint32_t ip = ntohl(network_addr.s_addr);
       ip <= ntohl(broadcast_addr.s_addr); ip++) {
    struct in_addr target_ip;
    target_ip.s_addr = htonl(ip);

    send_arp_request(sockfd, &device, &ip_addr, mac, &target_ip);
  }

  close(sockfd);
  return 0;
}
