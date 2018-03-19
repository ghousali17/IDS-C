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
	printf("Packet length:%d\n", len);
	u_short *ptr = ip;
	while (len > 1)
	{
		sum += *ptr;
		*ptr++;

		if (sum & 0x80000000) /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len) /* take care of left over byte */
		sum += (unsigned short)*(unsigned char *)ip;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

unsigned short mychecksum()
{
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
	unsigned int total_count = 0;
	unsigned int ip_count = 0;
	unsigned int valid_ip_count = 0;
	unsigned int udp_count = 0;
	unsigned int icmp_count = 0;
	unsigned int total_ip_payload = 0;
	unsigned short in_valid = 0;
	signal(SIGINT, close_program);
	if (argc != 6)
	{
		fprintf(stderr, "Usage: %s <interface> <h_pscan_thresh> <v_pscan_thresh> <epoch>\n", argv[0]);
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
	printf("Start capture at:%lf\n", cur_ts);
	while (close_p == 0)
	{

		if ((pkt = pcap_next(pcap, &hdr)) != NULL)
		{
			// get the timestamp
			pkt_ts = (double)hdr.ts.tv_usec / 1000000 + hdr.ts.tv_sec - cur_ts;
			total_count++;
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
			ip_count++; //total ip count increased.

			in_valid = (unsigned short)cksum(ip_hdr, (u_char)(ip_hdr->ip_hl) * 4);
			printf("Calculated checksum:%d\n", in_valid);
			if (in_valid == (unsigned short)0)
			{
				printf("IP packet valid!\n");
				valid_ip_count++;
			}
			else
			{   printf("------------------------------\n");
				sleep(5);}
			printf("Got loop!\n");
			// IP addresses are in network-byte order
			src_ip = ip_hdr->ip_src.s_addr;
			dst_ip = ip_hdr->ip_dst.s_addr;
			pkt_len = ntohs(ip_hdr->ip_len);

			if (ip_hdr->ip_p == IPPROTO_TCP)
			{
				tcp_count++;
				tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr +
											(ip_hdr->ip_hl << 2));
				src_port = ntohs(tcp_hdr->source);
				dst_port = ntohs(tcp_hdr->dest);

				//printf("Raw:%d -> %d\n",src_ip,dst_ip);
				printf("%3d |%lf|: %3d.%3d.%3d.%3d:%5d -> %3d.%3d.%3d.%3d:%5d [%d] [TCP:%4d]\n", ip_count,
					   pkt_ts,
					   src_ip & 0xff, (src_ip >> 8) & 0xff,
					   (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,
					   src_port,
					   dst_ip & 0xff, (dst_ip >> 8) & 0xff,
					   (dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff,
					   dst_port, pkt_len, tcp_count);
			}
			else if (ip_hdr->ip_p == IPPROTO_UDP)
			{
				udp_count++;
				udp_hdr = (struct udphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
				src_port = ntohs(udp_hdr->source);
				dst_port = ntohs(udp_hdr->dest);

				printf("%3d |%lf|: %3d.%3d.%3d.%3d:%5d -> %3d.%3d.%3d.%3d:%5d [%d] [UDP:%4d]\n", ip_count,
					   pkt_ts,
					   src_ip & 0xff, (src_ip >> 8) & 0xff,
					   (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,
					   src_port,
					   dst_ip & 0xff, (dst_ip >> 8) & 0xff,
					   (dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff,
					   dst_port, pkt_len, udp_count);
			}
			else if (ip_hdr->ip_p == IPPROTO_ICMP)
			{
				icmp_count++;
				icmp_hdr = (struct icmphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));

				printf("%3d |%lf|: %3d.%3d.%3d.%3d       -> %3d.%3d.%3d.%3d       [%d] [ICMP:%4d]\n", ip_count,
					   pkt_ts,
					   src_ip & 0xff, (src_ip >> 8) & 0xff,
					   (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,

					   dst_ip & 0xff, (dst_ip >> 8) & 0xff,
					   (dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff,
					   pkt_len, icmp_count);
			}
		}
	}

	// close files
	printf("---------------Final Statistics--------\n");
	printf("Total packets observed:%d\n", total_count);
	printf("Total IP packets observed:%d\n", ip_count);
	printf("Valid IP packets observed:%d\n", valid_ip_count);
	printf("TCP packets observed:%d\n", tcp_count);
	printf("UDP packets observed:%d\n", udp_count);
	printf("ICMP packets observed:%d\n", icmp_count);
	pcap_close(pcap);

	return 0;
}
