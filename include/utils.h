// Struct for queue
struct queue_item {
	size_t len;
	char frame_data[MAX_PACKET_LEN];
	int intidx;
};

int compare_mac(uint8_t *mac_addr1, uint8_t *mac_addr2);
int check_mac(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr);
int prefix_match(struct route_table_entry *entry, uint32_t dest_ip);
int is_specific(struct route_table_entry *entry1, struct route_table_entry *entry2);
int is_ip_in_cache(uint32_t dest_ip, struct arp_entry *arp_cache, size_t cache_size);
void copy_mac_address(uint8_t *dest_host, uint8_t *src_host);
size_t find_best_route_index(struct route_table_entry *rtable, size_t rtable_size, uint32_t dest_ip);
void update_arp_header_arp_reply(struct arp_header *arp_hdr, uint8_t my_mac[6]);
struct arp_entry create_arp_entry(struct arp_header *arp_hdr);
void add_arp_entry(struct arp_entry *arp_cache, size_t *arp_cache_size,
                   struct arp_entry new_entry);
void send_icmp(int intidx, char *frame_data, size_t len, struct iphdr *ip_hdr,
				struct ether_header *eth_hdr, uint8_t *my_mac, int type);
void reply_icmp(int intidx, char *frame_data, size_t len, struct icmphdr *icmp_hdr,
				struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t *my_mac);
void receive_arp(struct arp_header *arp_hdr, struct arp_entry *arp_cache,
                 size_t *arp_cache_size);
int handle_ttl_expired(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr,
						struct iphdr *ip_hdr, uint8_t *my_mac);
int handle_no_route(int intidx, char *frame_data, size_t len, struct ether_header *eth_hdr,
struct iphdr *ip_hdr, uint8_t *my_mac, struct route_table_entry *rtable, size_t rtable_size);
struct route_table_entry *initialize_rtable(char *arg, size_t *rtable_size);
struct arp_entry *initialize_cache(size_t *arp_cache_size);
struct route_table_entry *forward_route(struct route_table_entry *rtable,
										size_t rtable_size, uint32_t dest_ip);
void compute_icmp_header(int type, char *frame_data);
void compute_ip_header(struct iphdr *ip_hdr, int intidx);