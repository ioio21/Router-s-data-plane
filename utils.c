#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "include/utils.h"

// Compares two MAC addresses and returns 0 if they are equal,
// and 1 if they are not equal.
int compare_mac(uint8_t *mac_addr1, uint8_t *mac_addr2) {
    // Iterate over each byte of the MAC addresses and compare them
    for (int i = 0; i < 6; i++) {
        if (mac_addr1[i] != mac_addr2[i]) {
            return 1;
        }
    }
    return 0;
}

// Verifies if a frame's destination MAC address is either a broadcast address
// or the same as the MAC address of the receiving interface.
// Returns 1 if the MAC address is valid, or 0 otherwise.
int check_mac(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr) {
    // Get the MAC address of the receiving interface
    uint8_t my_mac[6];
    get_interface_mac(intidx, my_mac);

    // Define a broadcast MAC address
    uint8_t broadcast_mac[6];
    hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast_mac);

    // Check if the destination MAC address of the frame is either a
	// broadcast address or the same as the MAC address of the receiving interface
    if (compare_mac(eth_hdr->ether_dhost, broadcast_mac) != 0 &&
        compare_mac(eth_hdr->ether_dhost, my_mac) != 0) {
        // If the MAC address is invalid, return 0
        return 0;
    }

    // If the MAC address is valid, return 1
    return 1;
}

// Returns true if the given IP address matches the prefix and mask of the given route entry
int prefix_match(struct route_table_entry *entry, uint32_t dest_ip) {
    return (ntohl(dest_ip) & ntohl(entry->mask)) == ntohl(entry->prefix);
}

// Returns true if the mask of route entry 1 is more specific than that of route entry 2
int is_specific(struct route_table_entry *entry1, struct route_table_entry *entry2) {
    return ntohl(entry1->mask) > ntohl(entry2->mask);
}

// Check if the destination IP address matches an entry in the ARP cache
int is_ip_in_cache(uint32_t dest_ip, struct arp_entry *arp_cache, size_t cache_size) {
  for (size_t i = 0; i < cache_size; i++) {
    if (arp_cache[i].ip == dest_ip) {
      return i; // return the index of the matching entry
    }
  }
  return -1; // return -1 if no matching entry is found
}

// Copy the corresponding MAC address to dest_host
void copy_mac_address(uint8_t *dest_host, uint8_t *src_host) {
  memmove(dest_host, src_host, 6);
}

void update_arp_header_arp_reply(struct arp_header *arp_hdr, uint8_t my_mac[6]) {
	uint32_t tmp_addr;
    memmove(arp_hdr->tha, arp_hdr->sha, 6);
    memmove(arp_hdr->sha, my_mac, 6);
    tmp_addr = arp_hdr->spa;
    arp_hdr->spa = arp_hdr->tpa;
    arp_hdr->tpa = tmp_addr;
	arp_hdr->op = htons(2);
}

// Create arp entry for cache
struct arp_entry create_arp_entry(struct arp_header *arp_hdr) {
  struct arp_entry new_entry;
  new_entry.ip = arp_hdr->spa;
  memmove(new_entry.mac, arp_hdr->sha, 6);
  return new_entry;
}

// Add arp entry to cache
void add_arp_entry(struct arp_entry *arp_cache, size_t *arp_cache_size,
                   struct arp_entry new_entry) {
  arp_cache[*arp_cache_size] = new_entry;
  (*arp_cache_size)++;
}

// Save arp reply in cache
void receive_arp(struct arp_header *arp_hdr, struct arp_entry *arp_cache,
                 size_t *arp_cache_size) {
  struct arp_entry new_entry = create_arp_entry(arp_hdr);
  add_arp_entry(arp_cache, arp_cache_size, new_entry);
}

// Sends an ICMP packet with the specified type
void send_icmp(int intidx, char *frame_data, size_t len, struct iphdr *ip_hdr, struct ether_header *eth_hdr, uint8_t *my_mac, int type) {

	compute_icmp_header(type, frame_data);

	compute_ip_header(ip_hdr, intidx);

    // Update Ethernet header fields
    memmove(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memmove(eth_hdr->ether_shost, my_mac, 6);

    // Update the length of the Ethernet frame
    len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;

    // Send the packet
    send_to_link(intidx, frame_data, len);
}

// Sends an ICMP reply with the specified type
void reply_icmp(int intidx, char *frame_data, size_t len, struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t *my_mac) {

	// Update ICMP header fields
    icmp_hdr->checksum = 0; // Clear checksum field
    icmp_hdr->checksum = ntohs(checksum((uint16_t *)(frame_data + sizeof(struct ether_header) + sizeof(struct iphdr)), (sizeof(struct icmphdr) + 64))); // Calculate new checksum
	icmp_hdr->type = 0; // Echo reply type

    // Get the router's IP address for the current interface
    struct in_addr my_ip;
    inet_aton(get_interface_ip(intidx), &my_ip);

    // Update IP header fields
    ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = my_ip.s_addr;
	ip_hdr->ttl = 64;
    ip_hdr->check = htons(0);
    ip_hdr->check = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))); // Calculate new checksum

    // Update Ethernet header fields
    memmove(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memmove(eth_hdr->ether_shost, my_mac, 6);

    // Send packet
    send_to_link(intidx, frame_data, len);
}

int handle_ttl_expired(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t *my_mac) {
    // Verify that TTL is not 1 or 0
    if (ip_hdr->ttl == 1 || ip_hdr->ttl == 0) {
        // Send an ICMP "Time exceeded" message
        send_icmp(intidx, frame_data, len, ip_hdr, eth_hdr, my_mac, 11);
		return 1;
    }
	return 0;
}

int handle_no_route(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr,
 struct iphdr *ip_hdr, uint8_t *my_mac, struct route_table_entry *rtable, size_t rtable_size) {
    // If no entry for the destination IP is found in the routing table, send an ICMP "Destination unreacheable" message
    struct route_table_entry *best_route = forward_route(rtable, rtable_size, ip_hdr->daddr);
    if (best_route == NULL) {
        send_icmp(intidx, frame_data, len, ip_hdr, eth_hdr, my_mac, 3);
		return 1;
    }
	return 0;
}

struct route_table_entry *initialize_rtable(char *arg, size_t *rtable_size) {
	struct route_table_entry *rtable;
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	*rtable_size = read_rtable(arg, rtable);
	return rtable;
}

struct arp_entry *initialize_cache(size_t *arp_cache_size) {
	*arp_cache_size = 0;
	struct arp_entry *arp_cache;
	arp_cache = malloc(sizeof(struct arp_entry) * 50);
	return arp_cache;
}

void compute_icmp_header(int type, char *frame_data) {
	// Initialize ICMP header
    struct icmphdr icmp_hdr;
    icmp_hdr.code = 0;
    icmp_hdr.type = type;
    icmp_hdr.checksum = 0;

    // Move data to make room for ICMP header
    memmove(frame_data + sizeof(struct ether_header) + sizeof(struct iphdr) + 64, frame_data + sizeof(struct ether_header) + sizeof(struct iphdr), 64);

    // Compute ICMP checksum
    icmp_hdr.checksum = ntohs(checksum((uint16_t *)(frame_data + sizeof(struct ether_header) + sizeof(struct iphdr)), (sizeof(struct icmphdr) + 64)));

	// Add ICMP header
    memmove(frame_data + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_hdr, sizeof(struct icmphdr));
}

void compute_ip_header(struct iphdr *ip_hdr, int intidx) {
	// Set default values for IP header
    ip_hdr->tos = 0;
    ip_hdr->frag_off = 0;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->id = 1;

    // Update IP header fields
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->protocol = 1;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->ttl = 64;

    // Get the IP address of the interface
    struct in_addr my_ip;
    inet_aton(get_interface_ip(intidx), &my_ip);
    ip_hdr->saddr = my_ip.s_addr;

    // Compute IP header checksum
    ip_hdr->check = htons(0);
    ip_hdr->check = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
}

// Find the best route in the routing table for a given destination IP
size_t find_best_route_index(struct route_table_entry *rtable, size_t rtable_size, uint32_t dest_ip) {
    // Initialize the index to an invalid value
    size_t best_route_index = -1;

    // Iterate through the routing table entries
    for (size_t i = 0; i < rtable_size; i++) {
        if (prefix_match(&rtable[i], dest_ip)) {
            // If this is the first matching entry, it's the current best
            if (best_route_index == -1) {
                best_route_index = i;
            // Otherwise, compare the masks to determine which is more specific
            } else if (is_specific(&rtable[i], &rtable[best_route_index])) {
                best_route_index = i;
            }
        }
    }

    return best_route_index;
}

// Return a pointer to the best route or NULL if no matching entry was found.
struct route_table_entry *forward_route(struct route_table_entry *rtable, size_t rtable_size, uint32_t dest_ip) {
    size_t best_route_index = find_best_route_index(rtable, rtable_size, dest_ip);

    if (best_route_index == -1) {
        return NULL;
    }
    else {
        return &rtable[best_route_index];
    }
}
