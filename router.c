#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "include/utils.h"

// Find an ARP entry in the cache and copy its MAC address to dest_host
int find_arp_entry(struct arp_entry *arp_cache, size_t cache_size, uint32_t dest_ip, uint8_t *dest_host) {
  int index = is_ip_in_cache(dest_ip, arp_cache, cache_size);
  if (index >= 0) {
    copy_mac_address(dest_host, arp_cache[index].mac);
    return 1;
  }
  return 0;
}

// Sends an arp request
void arp_request(uint8_t *src_mac, uint32_t src_ip, uint8_t *dest_mac,
                      uint32_t dest_ip, int interface_index) {

	// Create a new packet
	int intidx;
	char frame_data[MAX_PACKET_LEN];
	size_t len;
	intidx = interface_index;

	// Initialize an Ethernet header for the new packet
	struct ether_header eth_hdr;
	memmove(eth_hdr.ether_dhost, dest_mac, 6);
	memmove(eth_hdr.ether_shost, src_mac, 6);
	eth_hdr.ether_type = htons(0x0806);

	// Initialize an ARP header for the new packet
	struct arp_header arp_hdr;
	arp_hdr.op = htons(1);
	arp_hdr.htype = htons(1);
	arp_hdr.hlen = 6;
	arp_hdr.ptype = htons(0x0800);
	arp_hdr.plen = 4;
	memmove(arp_hdr.sha, src_mac, 6);
	arp_hdr.spa = src_ip;
	arp_hdr.tpa = dest_ip;

	// Assemble the payload
	memmove(frame_data, &eth_hdr, sizeof(struct ether_header));
	memmove((frame_data + sizeof(struct ether_header)), &arp_hdr, sizeof(struct arp_header));

	len = sizeof(struct ether_header) + sizeof(struct arp_header);

	// Send the ARP request packet
	send_to_link(intidx, frame_data, len);
}

// Sends an ARP reply packet.
void arp_reply(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr, struct arp_header *arp_hdr) {
    
    // Get the MAC address corresponding to the interface on which the packet arrived
    uint8_t my_mac[6];
    get_interface_mac(intidx, my_mac);
    
    // Update the ARP header to send the reply
	update_arp_header_arp_reply(arp_hdr, my_mac);
    
    // Update the Ethernet header to send the reply
    memmove(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memmove(eth_hdr->ether_shost, my_mac, 6);
    
    // Send the packet
    send_to_link(intidx, frame_data, len);
}

// Sends packets from a queue if an ARP reply has been received for them
void send_from_cache(struct route_table_entry *rtable,
                        size_t rtable_size, struct arp_header *arp_hdr,
                        int *queue_in_use, queue q1,
						queue q2, queue queue_sel) {

    // Process each packet in the selected queue
    while (!queue_empty(queue_sel)) {

        // Dequeue the next packet in the selected queue
        struct queue_item *packet = (struct queue_item *)queue_deq(queue_sel);

        // Extract the IP header from the packet
        struct iphdr *ip_hdr = (struct iphdr *)(packet->frame_data + sizeof(struct ether_header));

        // Check if the next hop matches the ARP reply source IP address
        struct route_table_entry *best_route = forward_route(rtable, rtable_size, ip_hdr->daddr);
        if (best_route->next_hop != arp_hdr->spa) {
            // If the next hop doesn't match, enqueue the packet into the other queue
            if (*queue_in_use) {
                queue_enq(q2, (void *)packet);
            } else {
                queue_enq(q1, (void *)packet);
            }
            // Switch to the other queue if the current queue is empty
            if (queue_empty(queue_sel)) {
                *queue_in_use = !(*queue_in_use);
            }
            // Move to the next packet in the queue
            continue;
        }

        // Update the Ethernet header with the destination MAC address
        struct ether_header *eth_hdr = (struct ether_header*)(packet->frame_data);
        memmove(eth_hdr->ether_dhost, arp_hdr->sha, 6);

        // Send the packet
        send_to_link(packet->intidx, packet->frame_data, packet->len);

        // Move to the next packet in the queue
        continue;
    }
}

// Forward ipv4 packets
void ip_forwarding(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr, struct route_table_entry *rtable,
	size_t rtable_size, struct arp_entry *arp_cache, size_t *arp_cache_size, queue queue_sel) {
    
    // Find the MAC address corresponding to the incoming interface
	uint8_t my_mac[6];
	get_interface_mac(intidx, my_mac);

	// Initialize a broadcast MAC address
	uint8_t broadcast_mac[6];
	hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast_mac);

	// Extract the IP header
	struct iphdr *ip_hdr;
	ip_hdr = (struct iphdr *)(frame_data + sizeof(struct ether_header));

	// Find the IP address of the router on the current interface
	struct in_addr my_ip;
	inet_aton(get_interface_ip(intidx), &my_ip);

	// Check if this is an ICMP request, and if so, generate an ICMP reply
	struct icmphdr *icmp_hdr = (struct icmphdr *)(frame_data+ sizeof(struct ether_header) + sizeof(struct iphdr));
	if (ip_hdr->daddr == my_ip.s_addr && icmp_hdr->type == 8) {
		reply_icmp(intidx, frame_data, len, icmp_hdr, eth_hdr, ip_hdr, my_mac);
		return;
	}

	// Verify the IP header checksum
	uint16_t checksum3 = ip_hdr->check;
	ip_hdr->check = htons(0);
	uint16_t checksum2 = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	if (checksum2 != checksum3) {
		return;
	}
	ip_hdr->check = checksum3;

	// Verify that TTL is not 1 or 0
	if (handle_ttl_expired(intidx, frame_data, len, eth_hdr, ip_hdr, my_mac)) {
		return;
	}

	// Find the next hop from the routing table
	struct route_table_entry *best_route;
	best_route = forward_route(rtable, rtable_size, ip_hdr->daddr);

	// If no entry for the destination IP is found in the routing table, send an ICMP "Destination unreacheable" message
	if (handle_no_route(intidx, frame_data, len, eth_hdr, ip_hdr, my_mac, rtable, rtable_size)) {
		return;
	}
	// Update the MAC address with that of the current interface
	get_interface_mac(best_route->interface, my_mac);

	// Find the IP address of the current interface
	struct in_addr dest_ip;
	inet_aton(get_interface_ip(best_route->interface), &dest_ip);

	// Update the interface
	intidx = best_route->interface;

	// Decrement TTL
	ip_hdr->ttl--;

	// Update checksum
	ip_hdr->check = htons(0);
	ip_hdr->check = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// Rewrite Layer 2 addresses
	memmove(eth_hdr->ether_shost, my_mac, 6);
	uint8_t dhost[6];
	if (find_arp_entry(arp_cache, *arp_cache_size, best_route->next_hop, dhost) == 1) {
		memmove(eth_hdr->ether_dhost, dhost, 6);

		// Send packet
		send_to_link(intidx, frame_data, len);

	} else {

		// Send arp request and add it in queue
		arp_request(my_mac, dest_ip.s_addr, broadcast_mac, best_route->next_hop, best_route->interface);

		struct queue_item *msg = malloc(sizeof(struct queue_item ));
		memmove(&msg->intidx, &intidx, sizeof(int));
		memmove(msg->frame_data, frame_data, MAX_PACKET_LEN);
		memmove(&msg->len, &len, sizeof(size_t));
		queue_enq(queue_sel, (void *)msg);
	}
}

void is_arp(char *frame_data, int intidx, size_t len, struct ether_header *eth_hdr, 
	struct arp_entry *arp_cache, size_t *arp_cache_size, queue q1, queue q2, queue queue_sel, 
	struct route_table_entry *rtable, size_t rtable_size, int *queue_in_use) {
	
	// Extract ARP header
	struct arp_header *arp_hdr;
	arp_hdr = (struct arp_header *)(frame_data + sizeof(struct ether_header));

	// Check if it is arp request
	if (arp_hdr->op == htons(1)) {
		arp_reply(intidx, frame_data, len, eth_hdr, arp_hdr);
	// Check if it is arp reply
	} else if (arp_hdr->op == htons(2)) {
		receive_arp(arp_hdr, arp_cache, arp_cache_size);
		send_from_cache(rtable, rtable_size, arp_hdr, queue_in_use, q1, q2, queue_sel);
	}

}

int main(int argc, char *argv[]) {

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Initialize routing table
	size_t rtable_size;
	struct route_table_entry *rtable = initialize_rtable(argv[1], &rtable_size);

	// Initialize ARP cache
	size_t arp_cache_size;
	struct arp_entry *arp_cache = initialize_cache(&arp_cache_size);
	
	// Initialize packets queues
	int queue_in_use = 1;
	queue q1 = queue_create();
	queue q2 = queue_create();
	queue queue_sel;

	while (1) {

		int interface;
		size_t len;

		// Receive packet
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// Checking if the destination MAC address is the same as the one on
		// the interface where it was received or if the destination MAC address
		// is a broadcast type
		if (!check_mac(interface, buf, len, eth_hdr))
			continue;

		// Update queue in use
		if (queue_in_use)
			queue_sel = q1;
		else
			queue_sel = q2;

		// Check if it is ARP packet
		if (ntohs(eth_hdr->ether_type) == 0x0806) {
			
			is_arp(buf, interface, len, eth_hdr, arp_cache, &arp_cache_size, q1, q2, queue_sel, 
				rtable, rtable_size, &queue_in_use);

		// Check if it is IPv4 packet
		} else if (ntohs(eth_hdr->ether_type) == 0x0800) {
			ip_forwarding(interface, buf, len, eth_hdr, rtable, rtable_size, arp_cache, &arp_cache_size, queue_sel);
		}
	}
}
