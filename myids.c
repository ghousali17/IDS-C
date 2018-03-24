/*
 * sniffer.cc
 * - Use the libpcap library to write a sniffer.
 *   By Patrick P. C. Lee.
 */

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

#define ETH_HDR_LEN 14

typedef struct src_host
{
	uint32_t src_ip;
	uint32_t data_sent;		   //TOTAL IP PAYLOAD
	double HH_ts;			   //TIME STAMP FOR HEAVY HITTER INTRUSION DETECTION
	struct des_host **targets; //LIST OF DESTINATION HOST [NEEDED FOR VERTICAL PORT SCAN DETECTION]
	struct src_host *next;
} src_host;

typedef struct ids_param
{
	uint32_t HH_threshold; // HEAVY HITTER THRESHOLD
	uint32_t HS_threshold; // HORINTAL PORT SCAN THRESHOLD
	uint32_t VS_threshold; // VERTICAL PORT SCAN THRESHOLD

} ids_param;

typedef struct des_host
{
	uint32_t des_ip;
	uint16_t port_count; //PORTS OF THE HOST MACHINE TARGETED BY A SPECIFIC IP
	double VS_ts;		 // TIME STAMP FOR VERTICAL PORT SCAN DETECTION
	struct des_host *next;
	struct des_port **port; //LIST OF PORTS OF THE SPECIFIC HOST TARGETED BY SPECIFIC SOURCE

} des_host;

typedef struct hs_port
{
	uint16_t port_number;
	struct hs_port *next;
	uint32_t host_count;
	struct hs_src **sources;
	//

} hs_port;

typedef struct hs_src
{
	uint32_t src_ip;
	struct hs_src *next;
	uint32_t des_count;
	struct hs_des **targets;
	double HS_ts;
} hs_src;

typedef struct hs_des
{
	uint32_t des_ip;
	struct hs_des *next;

} hs_des;

typedef struct des_port
{
	uint16_t port;
	struct des_port *next;
} des_port;

struct src_host *HEAD_LIST_ONE = NULL; //list of lists for tracking HH and VS
struct hs_port *HEAD_LIST_TWO = NULL;  // list of lists for tracking HS

void ip_format(char *ip_address);
void print_des(des_host *head);
void print_list_one();
void print_port(des_port *head);
void report_HH_VS();
void hs_insert_src(struct ip *ip_hdr, struct hs_src **head, double pkt_ts, struct ids_param ids);
int insert_port(struct des_port **head, uint16_t port_number);
void insert_des(struct des_host **head, uint32_t des_ip, uint16_t port_number, double pkt_ts, struct ids_param);
void insert_src(struct ip *ip_hdr, uint32_t payload, uint16_t port_number, double pkt_ts, struct ids_param ids);
void hs_insert_port(struct ip *ip_hdr, uint32_t port_number, double pkt_ts, struct ids_param ids);
int hs_insert_des(struct ip *ip_hdr, struct hs_des **head);
void report_HS();

/****************************************************FUNCTION INSERTION IN LIST ONE [HH and VS]***********************************************************/
//Inserts the Source IP (level 1) in List one
void insert_src(struct ip *ip_hdr, uint32_t payload, uint16_t port_number, double pkt_ts, struct ids_param ids)
{
	uint32_t src_ip = ip_hdr->ip_src.s_addr;
	uint32_t des_ip = ip_hdr->ip_dst.s_addr;
	src_host *new_node = (src_host *)malloc(sizeof(src_host));
	new_node->next = NULL;
	new_node->targets = (des_host **)malloc(sizeof(des_host *));
	*(new_node->targets) = NULL;
	new_node->src_ip = src_ip;
	new_node->data_sent = payload;
	new_node->HH_ts = -1;

	if (HEAD_LIST_ONE == NULL)
	{

		HEAD_LIST_ONE = new_node;
	}
	else
	{
		src_host *pre_node = NULL;
		src_host *cur_node = HEAD_LIST_ONE;
		while (cur_node != NULL)
		{
			pre_node = cur_node;
			if (cur_node->src_ip == src_ip)
			{
				cur_node->data_sent += payload;

				insert_des(cur_node->targets, des_ip, port_number, pkt_ts, ids);
				if (cur_node->data_sent >= ids.HH_threshold)
				{
					if (cur_node->HH_ts == -1)
						cur_node->HH_ts = pkt_ts;
				}
				return;
			}
			cur_node = cur_node->next;
		}

		pre_node->next = new_node;
	}
	if (payload >= ids.HH_threshold)
	{

		new_node->HH_ts = pkt_ts;
	}
	insert_des(new_node->targets, des_ip, port_number, pkt_ts, ids);
	return;
}

//Inserts Destination IP (Level 2) in List One
void insert_des(struct des_host **head, uint32_t des_ip, uint16_t port_number, double pkt_ts, struct ids_param ids)
{
	uint32_t VS_threshold = ids.VS_threshold;
	des_host *new_node = (des_host *)malloc(sizeof(des_host));
	new_node->port = (des_port **)malloc(sizeof(des_port));
	new_node->next = NULL;
	new_node->des_ip = des_ip;
	new_node->port_count = 0;
	new_node->VS_ts = -1; // -1 to indicate the absence of ports [ICMP MESSAGES]

	if (*head == NULL)
	{

		*head = new_node;
	}
	else
	{
		des_host *pre_node = NULL;
		des_host *cur_node = *head;
		while (cur_node != NULL)
		{
			pre_node = cur_node;
			if (cur_node->des_ip == des_ip)
			{
				if (insert_port(cur_node->port, port_number) == 1)
				{
					cur_node->port_count++;
					if (cur_node->port_count >= VS_threshold)
					{
						if (cur_node->VS_ts == -1)
						{
							cur_node->VS_ts = pkt_ts;
						}
					}
				}
				return;
			}
			cur_node = cur_node->next;
		}
		pre_node->next = new_node;
	}
	if (insert_port(new_node->port, port_number) == 1)
	{
		new_node->port_count++;
		if (new_node->port_count >= VS_threshold)
		{
			new_node->VS_ts = pkt_ts;
		}
	}
	return;
}

//Inserts Port number (Level 3) in List One
int insert_port(struct des_port **head, uint16_t port_number)
{
	if (port_number == (uint16_t)-1) // -1 indicates that packets is ICMP
	{

		return 0;
	}
	if (*head == NULL)
	{
		struct des_port *new_node = (des_port *)malloc(sizeof(des_port));
		new_node->next = NULL;
		new_node->port = port_number;
		*head = new_node;
	}
	else
	{
		des_port *cur_node = *head;
		des_port *pre_node = NULL;
		while (cur_node != NULL)
		{
			pre_node = cur_node;
			if (cur_node->port == port_number)
			{

				return 0;
			}
			cur_node = cur_node->next;
		}

		struct des_port *new_node = (des_port *)malloc(sizeof(des_port));
		new_node->next = NULL;
		new_node->port = port_number;
		pre_node->next = new_node;
	}
	return 1;
}
/**************************************************************************************************************************************/
/***************************************************FUNCTIONS TO PRINT LIST FOR HH AND VS**********************************************/
void print_list_one()
{
	int count = 1;
	char ip_address_sender[16];
	src_host *temp = HEAD_LIST_ONE;
	uint32_t src_ip;
	while (temp != NULL)
	{
		src_ip = temp->src_ip;
		sprintf(ip_address_sender, "%d.%d.%d.%d", src_ip & 0xff, (src_ip >> 8) & 0xff,
				(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
		ip_format(ip_address_sender);
		printf("%d %s  %d bytes\n", count++, ip_address_sender, temp->data_sent);
		printf("Target:\n");
		print_des(*(temp->targets));
		temp = temp->next;
	}
}

void print_des(des_host *head)
{
	char ip_address_sender[16];
	des_host *temp = head;
	uint32_t des_ip;
	while (temp != NULL)
	{
		des_ip = temp->des_ip;
		sprintf(ip_address_sender, "%d.%d.%d.%d", des_ip & 0xff, (des_ip >> 8) & 0xff,
				(des_ip >> 16) & 0xff, (des_ip >> 24) & 0xff);
		ip_format(ip_address_sender);
		printf("%s [%d]\n", ip_address_sender, temp->port_count);
		print_port(*(temp->port));
		temp = temp->next;
	}
	printf("\n");
}

void print_port(des_port *head)
{
	des_port *temp = head;
	while (temp != NULL)
	{

		printf("%u ", temp->port);
		temp = temp->next;
	}
	printf("\n");
}

/*****************************************************INTRUSION DETECTION FUNCTIONS**********************************************************/


void report_HS()
{
	char ip_address_sender[16];

	uint32_t src_ip;
	uint16_t port_number;
	double HS_ts;
	struct hs_port *PORT_ptr = HEAD_LIST_TWO;
	struct hs_src *SRC_ptr;
	while (PORT_ptr != NULL)
	{
		port_number = PORT_ptr->port_number;
		SRC_ptr = *(PORT_ptr->sources);
		while (SRC_ptr != NULL)
		{
			src_ip = SRC_ptr->src_ip;
			sprintf(ip_address_sender, "%u.%u.%u.%u", src_ip & 0xff, (src_ip >> 8) & 0xff,
					(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
			ip_format(ip_address_sender);
			HS_ts = SRC_ptr->HS_ts;
			if (HS_ts != (double)-1) // -1 is initialk value of TS so if TS = -1 means no intrusion detected while inserting
			{
				printf("%012lf| TYPE HORIZONTAL SCAN| Source:%s | Target Port: %u| [%d]\n", HS_ts, ip_address_sender, port_number, SRC_ptr->des_count);
			}
			SRC_ptr = SRC_ptr->next;
		}
		PORT_ptr = PORT_ptr->next;
	}
}
void report_HH_VS()
{
	printf("Intrusions:\n");

	char ip_address_sender[16];
	char ip_address_receiver[16];
	uint32_t src_ip;
	uint32_t des_ip;
	uint32_t payload;
	double pkt_ts;
	double vs_ts;
	struct src_host *HH_ptr = HEAD_LIST_ONE;
	struct des_host *VS_ptr = NULL;
	while (HH_ptr != NULL)
	{
		VS_ptr = *(HH_ptr->targets);
		pkt_ts = HH_ptr->HH_ts;
		if (pkt_ts != -1)
		{
			src_ip = HH_ptr->src_ip;

			payload = HH_ptr->data_sent;
			sprintf(ip_address_sender, "%u.%u.%u.%u", src_ip & 0xff, (src_ip >> 8) & 0xff,
					(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
			ip_format(ip_address_sender);

			printf("%012lf| TYPE: HEAVY HITTER | Source:%s | Payload: %d |\n", pkt_ts, ip_address_sender, payload);
		}
		while (VS_ptr != NULL)
		{
			vs_ts = VS_ptr->VS_ts;
			if (vs_ts != -1)
			{
				src_ip = HH_ptr->src_ip;
				des_ip = VS_ptr->des_ip;

				payload = VS_ptr->port_count;
				sprintf(ip_address_sender, "%u.%u.%u.%u", src_ip & 0xff, (src_ip >> 8) & 0xff,
						(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
				ip_format(ip_address_sender);
				sprintf(ip_address_receiver, "%u.%u.%u.%u", des_ip & 0xff, (des_ip >> 8) & 0xff,
						(des_ip >> 16) & 0xff, (des_ip >> 24) & 0xff);
				ip_format(ip_address_receiver);

				printf("%012lf| TYPE: VERTICAL SCANNER| Source: %s | Destination: %s |\n", vs_ts, ip_address_sender, ip_address_receiver);
			}

			VS_ptr = VS_ptr->next;
		}
		HH_ptr = HH_ptr->next;
	}
}
/***********************************************************************************************************************************************/
/************************************************FUNCTIONS FOR INSERTION IN LIST TWO [HORIZONTAL SCAN]********************************************************/
void hs_insert_port(struct ip *ip_hdr, uint32_t port_number, double pkt_ts, struct ids_param ids)
{
	struct hs_port *new_node = (struct hs_port *)malloc(sizeof(struct hs_port));
	new_node->port_number = port_number;
	new_node->host_count = 0;
	new_node->next = NULL;

	new_node->sources = (struct hs_src **)malloc(sizeof(struct hs_src *));
	if (HEAD_LIST_TWO == NULL)
	{
		HEAD_LIST_TWO = new_node;
	}
	else
	{
		struct hs_port *cur_node = HEAD_LIST_TWO;
		struct hs_port *pre_node = NULL;
		while (cur_node != NULL)
		{
			pre_node = cur_node;
			if (cur_node->port_number == port_number)
			{
				hs_insert_src(ip_hdr, cur_node->sources, pkt_ts, ids);
				return;
			}
			cur_node = cur_node->next;
		}
		pre_node->next = new_node;
	}
	hs_insert_src(ip_hdr, new_node->sources, pkt_ts, ids);
}

void hs_insert_src(struct ip *ip_hdr, struct hs_src **head, double pkt_ts, struct ids_param ids)
{
	uint32_t src_ip = ip_hdr->ip_src.s_addr;
	struct hs_src *new_node = (struct hs_src *)malloc(sizeof(struct hs_src));
	new_node->next = NULL;
	new_node->src_ip = src_ip;
	new_node->des_count = 0;
	new_node->targets = (struct hs_des **)malloc(sizeof(struct hs_des *));
	new_node->HS_ts = (double)-1;

	if (*head == NULL)
	{

		*head = new_node;
	}
	else
	{
		struct hs_src *cur_node = *head;
		struct hs_src *pre_node = NULL;
		while (cur_node != NULL)
		{
			pre_node = cur_node;
			if (cur_node->src_ip == src_ip)
			{
				if (hs_insert_des(ip_hdr, cur_node->targets) == 1)
				{
					cur_node->des_count++;
					if (cur_node->des_count >= ids.HS_threshold)
					{
						if (cur_node->HS_ts == -1)
						{
							cur_node->HS_ts = pkt_ts;
						}
					}
				}

				return;
			}

			cur_node = cur_node->next;
		}
		pre_node->next = new_node;
	}
	new_node->des_count++;
	hs_insert_des(ip_hdr, new_node->targets);
	if (new_node->des_count >= ids.HS_threshold)
	{
		new_node->HS_ts = pkt_ts;
	}
}
int hs_insert_des(struct ip *ip_hdr, struct hs_des **head)
{

	uint32_t des_ip = ip_hdr->ip_dst.s_addr;
	struct hs_des *new_node = (struct hs_des *)malloc(sizeof(hs_des));
	new_node->next = NULL;
	new_node->des_ip = des_ip;

	if (*head == NULL)
	{

		*head = new_node;
	}
	else
	{
		struct hs_des *cur_node = *head;
		struct hs_des *pre_node = NULL;
		while (cur_node != NULL)
		{
			pre_node = cur_node;
			if (cur_node->des_ip == des_ip)
			{

				return 0;
			}
			cur_node = cur_node->next;
		}
		pre_node->next = new_node;
	}
	return 1;
}

/*************************************************************************************************************************************************/
int close_p;
void close_program(int signal)
{

	close_p = 1;
}

unsigned short cksum(struct ip *ip, int len)
{
	long sum = 0; /* assume 32 bit long, 16 bit short */

	u_short *ptr = ip; //ptr to ip packet (16 bit increment)
	while (len > 1)
	{
		sum += *ptr;
		*ptr++;

		if (sum & 0x80000000)					/* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16); //16bit hexadecimal addition
		len -= 2;
	}

	if (len) /* take care of left over byte */
		sum += (unsigned short)*(unsigned char *)ip;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

void ip_format(char *ip_address) //converts ip string into a formatted ip string
{
	int len = strlen(ip_address);
	int padding = 15 - len;
	int i;

	for (i = 0; i < padding; i++)
	{

		strcat(ip_address, " ");
	}
	return;
}

void print_list_two()
{
	printf("Distinct ports targeted:\n");
	struct hs_port *PORT_ptr = HEAD_LIST_TWO;
	struct hs_src *SRC_ptr = NULL;
	struct hs_des *DES_ptr = NULL;
	char ip_address_sender[16];
	char ip_address_receiver[16];
	uint32_t src_ip;
	uint32_t des_ip;

	while (PORT_ptr != NULL)
	{
		printf("%u\n", PORT_ptr->port_number);

		SRC_ptr = *PORT_ptr->sources;
		while (SRC_ptr != NULL)
		{
			src_ip = SRC_ptr->src_ip;
			sprintf(ip_address_sender, "%u.%u.%u.%u", src_ip & 0xff, (src_ip >> 8) & 0xff,
					(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
			ip_format(ip_address_sender);
			printf("%s [%d]\n", ip_address_sender, SRC_ptr->des_count);
			DES_ptr = *SRC_ptr->targets;
			printf("host:\n");
			while (DES_ptr != NULL)
			{
				des_ip = DES_ptr->des_ip;
				sprintf(ip_address_receiver, "%u.%u.%u.%u", des_ip & 0xff, (des_ip >> 8) & 0xff,
						(des_ip >> 16) & 0xff, (des_ip >> 24) & 0xff);
				ip_format(ip_address_receiver);
				printf("%s ", ip_address_receiver);
				DES_ptr = DES_ptr->next;
			}
			SRC_ptr = SRC_ptr->next;
		}
		printf("\n");
		PORT_ptr = PORT_ptr->next;
	}
}
/***************************************************************************
 * Main program
 ***************************************************************************/
int main(int argc, char **argv)
{
	close_p = 0;
	pcap_t *pcap;
	char errbuf[256];
	struct pcap_pkthdr hdr;
	const u_char *pkt; // raw packet
	double pkt_ts;
	; // raw packet timestamp
	double cur_ts;
	struct timeval *cur_time = (struct timeval *)malloc(sizeof(struct timeval));

	struct ether_header *eth_hdr = NULL;
	struct ip *ip_hdr = NULL;
	struct tcphdr *tcp_hdr = NULL;
	struct udphdr *udp_hdr = NULL;
	struct icmphdr *icmp_hdr = NULL;
	struct ids_param ids;
	ids.HH_threshold = atoi(argv[2]);
	ids.HS_threshold = atoi(argv[3]);
	ids.VS_threshold = atoi(argv[4]);

	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short pkt_len;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int epoch;
	unsigned int tcp_count = 0;
	unsigned int frame_count = 0;
	unsigned int total_ip_count = 0;
	unsigned int valid_ip_count = 0;
	//unsigned int total_ip_payload = 0;
	unsigned int udp_count = 0;
	unsigned int icmp_count = 0;
	unsigned short ip_validation = 0;
	char ip_address_sender[16];
	char ip_address_receiver[16];
	double epoch_tracker;

	signal(SIGINT, close_program);
	if (argc != 6)
	{
		fprintf(stderr, "Usage: %s <trace_file_name> <hh_threshold> ><h_pscan_thresh> <v_pscan_thresh> <epoch>\n", argv[0]);
		exit(-1);
	}
	epoch = atoi(argv[5]) * 1000;
	printf("Setting epoch to %d\n", epoch);

	// open input pcap file
	if ((pcap = pcap_open_offline_with_tstamp_precision(argv[1],
														PCAP_TSTAMP_PRECISION_MICRO, errbuf)) == NULL)
	//	if ((pcap = pcap_open_live(argv[1], 1500, 1, epoch, errbuf)) == NULL)
	{
		fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[1], errbuf);
		exit(-1);
	}

	pcap_setnonblock(pcap, 1, errbuf);
	gettimeofday(cur_time, NULL);
	cur_ts = -1; //(double)cur_time->tv_usec / 1000000 + cur_time->tv_sec;
	epoch_tracker = epoch / 1000;
	printf("Starting capture at: %lf\n", cur_ts);
	//	while (close_p == 0)
	{
		ip_hdr = NULL; //re initialises IP header after every packet analysis.

		while ((pkt = pcap_next(pcap, &hdr)) != NULL)
		{
			if (cur_ts == -1)
			{

				cur_ts = (double)hdr.ts.tv_usec / 1000000 + hdr.ts.tv_sec;
			}
			// get the timestamp
			pkt_ts = (double)hdr.ts.tv_usec / 1000000 + hdr.ts.tv_sec - cur_ts;
			if (pkt_ts > epoch_tracker)
			{
				while (pkt_ts > (epoch_tracker))
				{
					printf("Epoch summary list at %lf\n", pkt_ts);
					print_list_one();
					print_list_two();
					report_HH_VS();
					report_HS();
					printf("\n");
					HEAD_LIST_ONE = NULL;
					HEAD_LIST_TWO = NULL;
					//  printf("Called print!\n");
					epoch_tracker += epoch / 1000;
				}
			}
			frame_count++;
			// parse the headers

			eth_hdr = (struct ether_header *)pkt;
			switch (ntohs(eth_hdr->ether_type))
			{
			case ETH_P_IP: // IP packets (no VLAN header)
				ip_hdr = (struct ip *)(pkt + ETH_HDR_LEN);
				break;
			case 0x8100: // with VLAN header (with 4 bytes)
				ip_hdr = (struct ip *)(pkt + ETH_HDR_LEN + 4);
				break;
			}

			// if IP header is NULL (not IP or VLAN), continue.
			if (ip_hdr == NULL)
			{
				continue;
			}
			total_ip_count++; //total ip count increased.

			ip_validation = (unsigned short)cksum(ip_hdr, (u_char)(ip_hdr->ip_hl) * 4);

			if (ip_validation == (unsigned short)0)
			{

				valid_ip_count++;
			}
			else
			{
				printf("Invalid IP Packet:%d\n", total_ip_count);
				continue;
			}

			// IP addresses are in network-byte order
			src_ip = ip_hdr->ip_src.s_addr;
			dst_ip = ip_hdr->ip_dst.s_addr;
			pkt_len = ntohs(ip_hdr->ip_len);

			sprintf(ip_address_sender, "%u.%u.%u.%u", src_ip & 0xff, (src_ip >> 8) & 0xff,
					(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
			sprintf(ip_address_receiver, "%u.%u.%u.%u", dst_ip & 0xff, (dst_ip >> 8) & 0xff,
					(dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff);

			ip_format(ip_address_sender);
			ip_format(ip_address_receiver);
			if (ip_hdr->ip_p == IPPROTO_TCP)
			{
				tcp_count++;
				tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr +
											(ip_hdr->ip_hl << 2));
				src_port = ntohs(tcp_hdr->source);
				dst_port = ntohs(tcp_hdr->dest);
				insert_src(ip_hdr, pkt_len, dst_port, pkt_ts, ids);
				hs_insert_port(ip_hdr, dst_port, pkt_ts, ids);
				printf("%3d |%012lf| %s-->%s |%5d|[TCP :%4d]|%05d->%05d|\n", total_ip_count,
					   pkt_ts,
					   ip_address_sender, ip_address_receiver,
					   pkt_len, tcp_count, src_port, dst_port);
			}
			else if (ip_hdr->ip_p == IPPROTO_UDP)
			{
				udp_count++;
				udp_hdr = (struct udphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
				src_port = ntohs(udp_hdr->source);
				dst_port = ntohs(udp_hdr->dest);
				insert_src(ip_hdr, pkt_len, dst_port, pkt_ts, ids);
				hs_insert_port(ip_hdr, dst_port, pkt_ts, ids);
				printf("%3d |%012lf| %s-->%s |%5d|[UDP :%4d]|%05d->%05d|\n", total_ip_count,
					   pkt_ts,
					   ip_address_sender, ip_address_receiver,
					   pkt_len, udp_count, src_port, dst_port);
			}
			else if (ip_hdr->ip_p == IPPROTO_ICMP)
			{
				icmp_count++;
				icmp_hdr = (struct icmphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
				insert_src(ip_hdr, pkt_len, -1, pkt_ts, ids);
				printf("%3d |%012lf| %s-->%s |%5d|[ICMP:%4d]|\n", total_ip_count,
					   pkt_ts,
					   ip_address_sender, ip_address_receiver,
					   pkt_len, icmp_count);
			}
		}
	}
	//intrusion in the last epoch
	print_list_one();
	print_list_two();
	report_HH_VS();
	report_HS();
	printf("\n");
	HEAD_LIST_ONE = NULL;
	HEAD_LIST_TWO = NULL;
	//final summary
	printf("---------------Final Statistics---------------\n");
	printf("Total frames observed:%d\n", frame_count);
	printf("Total IP packets observed:%d\n", total_ip_count);
	printf("Valid IP packets observed:%d\n", valid_ip_count);
	printf("TCP packets observed:%d\n", tcp_count);
	printf("UDP packets observed:%d\n", udp_count);
	printf("ICMP packets observed:%d\n", icmp_count);

	pcap_close(pcap);

	return 0;
}
