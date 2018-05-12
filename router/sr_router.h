/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void sr_handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

void set_ethernet_src_dst(sr_ethernet_hdr_t * ethernet_header, uint8_t * new_src, uint8_t * new_dst);
void set_arp_sha_tha(sr_arp_hdr_t * arp_header, unsigned char * new_sha, unsigned char * new_tha);
int arp_cache_check_add_queue_remove (struct sr_arpcache *cache, unsigned char *mac, uint32_t ip);
struct sr_rt * longest_prefix_match(struct sr_instance* sr, uint8_t * packet);
void handle_send_to_next_hop_ip(struct sr_instance* sr,
  uint8_t * packet,
  unsigned int len,  
  struct sr_rt * routing_entry);
void handle_ip_packets_for_us(struct sr_instance* sr, uint8_t * packet, unsigned int len);
void arp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
int is_arp_reply_for_us(struct sr_instance* sr, uint8_t * packet);
int is_ip_packet_matches_interfaces(struct sr_instance* sr, uint8_t * packet);
int is_ttl_valid(uint8_t * packet);

void modify_send_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t type, uint8_t code);
void put_ip_header_in_icmp_data(uint8_t * data, sr_ip_hdr_t * ip_header);
void set_ip_header_fields_new_icmp(sr_ip_hdr_t * ip_header, sr_ip_hdr_t * old_ip_header, size_t icmp_size);
void send_new_icmp_type11(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void set_fields_in_icmp_type11_header(sr_icmp_t11_hdr_t * type11_icmp_header);

void modify_send_icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void send_icmp_time_exceeded(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void modify_send_icmp_type3(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t code);
void modify_send_icmp_port_unreachable(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void modify_send_icmp_net_unreachable(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void modify_send_icmp_host_unreachable(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
int handle_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
int handle_ip_for_us(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
int is_ip_checksum_valid (uint8_t * packet);
struct sr_arpentry * arp_cache_contains_entry(struct sr_instance* sr, struct sr_rt * entry);
void forward_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, unsigned char * dest_mac);
void send_arp_req_packets(struct sr_instance* sr, struct sr_arpreq * req, unsigned char * dest_mac);
/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
