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

void ip_format(char *ip_address)
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
	unsigned int total_ip_payload = 0;
	unsigned int udp_count = 0;
	unsigned int icmp_count = 0;
	unsigned short ip_validation = 0;
	unsigned char ip_address_sender[16];
	unsigned char ip_address_receiver[16];
	signal(SIGINT, close_program);
	if (argc != 6)
	{
		fprintf(stderr, "Usage: %s <interface> <hh_threshold> ><h_pscan_thresh> <v_pscan_thresh> <epoch>\n", argv[0]);
		exit(-1);
	}
	epoch = atoi(argv[5]) * 1000;
	printf("Setting epoch to %d\n", epoch);

	// open input pcap file
	if ((pcap = pcap_open_live(argv[1], 1500, 1, epoch, errbuf)) == NULL)
	{
		fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[1], errbuf);
		exit(-1);
	}

	pcap_setnonblock(pcap, 1, errbuf);
	gettimeofday(cur_time, NULL);
	cur_ts = (double)cur_time->tv_usec / 1000000 + cur_time->tv_sec;
	printf("Starting capture at: %lf\n", cur_ts);
	while (close_p == 0)
	{
		ip_hdr = NULL; //re initialises IP header after every packet analysis.

		if ((pkt = pcap_next(pcap, &hdr)) != NULL)
		{
			// get the timestamp
			pkt_ts = (double)hdr.ts.tv_usec / 1000000 + hdr.ts.tv_sec - cur_ts;
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
				break;
			}

			// IP addresses are in network-byte order
			src_ip = ip_hdr->ip_src.s_addr;
			dst_ip = ip_hdr->ip_dst.s_addr;
			pkt_len = ntohs(ip_hdr->ip_len);
			sprintf(ip_address_sender, "%d.%d.%d.%d", src_ip & 0xff, (src_ip >> 8) & 0xff,
					(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
			sprintf(ip_address_receiver, "%d.%d.%d.%d", dst_ip & 0xff, (dst_ip >> 8) & 0xff,
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
				printf("%3d |%012lf| %s-->%s |%5d|[UDP :%4d]|%05d->%05d|\n", total_ip_count,
					   pkt_ts,
					   ip_address_sender,ip_address_receiver,
					   pkt_len, udp_count, src_port, dst_port);
			}
			else if (ip_hdr->ip_p == IPPROTO_ICMP)
			{
				icmp_count++;
				icmp_hdr = (struct icmphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));

				printf("%3d |%012lf| %s-->%s |%5d|[ICMP:%4d]|\n", total_ip_count,
					   pkt_ts,
					   ip_address_sender, ip_address_receiver,
					   pkt_len, icmp_count);
			}
		}
	}

	// close files
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
