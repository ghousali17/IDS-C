#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#ifndef IDS_H
#define IDS_H 

#define ETH_HDR_LEN 14

typedef struct ids_param {
	long double HH_threshold; // HEAVY HITTER THRESHOLD
	uint32_t HS_threshold; // HORINTAL PORT SCAN THRESHOLD
	uint32_t VS_threshold; // VERTICAL PORT SCAN THRESHOLD

} ids_param;

typedef struct src_host {
	uint32_t src_ip;
	uint32_t data_sent;		   //TOTAL IP PAYLOAD
	double HH_ts;			   //TIME STAMP FOR HEAVY HITTER INTRUSION DETECTION
	struct des_host **targets; //LIST OF DESTINATION HOST [NEEDED FOR VERTICAL PORT SCAN DETECTION]
	struct src_host *next;
} src_host;


typedef struct des_host {
	uint32_t des_ip;
	uint16_t port_count; //PORTS OF THE HOST MACHINE TARGETED BY A SPECIFIC IP
	double VS_ts;		 // TIME STAMP FOR VERTICAL PORT SCAN DETECTION
	struct des_port **port; //LIST OF PORTS OF THE SPECIFIC HOST TARGETED BY SPECIFIC SOURCE
	struct des_host *next;

} des_host;

typedef struct des_port {
	uint16_t port;
	struct des_port *next;
} des_port;

typedef struct hs_port {
	uint16_t port_number;
	uint32_t host_count;
	struct hs_src **sources;
	struct hs_port *next;

} hs_port;

typedef struct hs_src {
	uint32_t src_ip;
	uint32_t des_count;
	struct hs_des **targets;
	double HS_ts;
	struct hs_src *next;
} hs_src;

typedef struct hs_des {
	uint32_t des_ip;
	struct hs_des *next;

} hs_des;

void ip_format(char *ip_address);
unsigned short ip_checksum(unsigned char *iphdr);
unsigned short in_cksum(unsigned short* addr, int len);
void report_HH_VS();
void report_HS();
void hs_insert_src(struct ip *ip_hdr, struct hs_src **head, double pkt_ts, struct ids_param ids);
int insert_port(struct des_port **head, uint16_t port_number);
void insert_des(struct des_host **head, uint32_t des_ip, uint16_t port_number, double pkt_ts, struct ids_param);
void insert_src(struct ip *ip_hdr, uint32_t payload, uint16_t port_number, double pkt_ts, struct ids_param ids);
void hs_insert_port(struct ip *ip_hdr, uint32_t port_number, double pkt_ts, struct ids_param ids);
int hs_insert_des(struct ip *ip_hdr, struct hs_des **head);
void cleanup();

#endif
