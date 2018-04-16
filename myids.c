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
#include "ids.h"


int close_p;
void close_program(int signal)
{
	close_p = 1;
}


int main(int argc, char **argv)
{
	close_p = 0;
	pcap_t *pcap;
	char errbuf[256];
	struct pcap_pkthdr hdr;
	const u_char *pkt; // raw packet
	double pkt_ts; // raw packet timestamp
	double cur_ts;
	struct timeval *cur_time = (struct timeval *)malloc(sizeof(struct timeval));

	struct ether_header *eth_hdr = NULL;
	struct ip *ip_hdr = NULL;
	struct tcphdr *tcp_hdr = NULL;
	struct udphdr *udp_hdr = NULL;
	struct ids_param ids;

	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short pkt_len;
	unsigned short src_port;
	unsigned short dst_port;
	double epoch;
	unsigned int tcp_count = 0;
	unsigned int frame_count = 0;
	unsigned int total_ip_count = 0;
	unsigned int valid_ip_count = 0;
	unsigned long total_ip_payload = 0;
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
	if (atoi(argv[2]) < 0 && atoi(argv[3]) < 0 && atoi(argv[4]) < 0 && atoi(argv[5]) < 0) {
		fprintf(stderr, "Usage: %s <trace_file_name> <hh_threshold> ><h_pscan_thresh> <v_pscan_thresh> <epoch>\n", argv[0]);
		exit(-1);	
	}
	ids.HH_threshold = atof(argv[2]) * 1000000;
	ids.HS_threshold = atoi(argv[3]);
	ids.VS_threshold = atoi(argv[4]);
	epoch = atof(argv[5]) * 1000;


	// open input pcap file
	if ((pcap = pcap_open_offline_with_tstamp_precision(argv[1],
				PCAP_TSTAMP_PRECISION_MICRO, errbuf)) == NULL) {
		fprintf(stderr, "ERR: cannot open %s (%s)\n", argv[1], errbuf);
		exit(-1);
	}

	pcap_setnonblock(pcap, 1, errbuf);
	gettimeofday(cur_time, NULL);
	cur_ts = -1; 
	epoch_tracker = epoch / 1000;

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
				printf("\n======================================================EPOCH SUMMARY======================================================\n\n");
				report_HH_VS();
				report_HS();
				printf("\n=========================================================================================================================\n\n");
				cleanup();

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
			default:
				ip_hdr = NULL;
		}

		// if IP header is NULL (not IP or VLAN), continue.
		if (ip_hdr == NULL)
			continue;

		total_ip_count++; //total ip count increased.

		ip_validation = htons((unsigned short) ip_checksum((unsigned char *)ip_hdr));

		if (htons(ip_hdr->ip_sum) == ip_validation) {
			valid_ip_count++;
		} else
		{
			printf("Invalid IP Packet Checksum:%d 	(%x,%x)\n",
					total_ip_count, htons((unsigned short) ip_hdr->ip_sum), ip_validation);
			continue;
		}

		// IP addresses are in network-byte order
		src_ip = ip_hdr->ip_src.s_addr;
		dst_ip = ip_hdr->ip_dst.s_addr;
		pkt_len = ntohs(ip_hdr->ip_len) - (unsigned char)(ip_hdr->ip_hl << 2);
		total_ip_payload += pkt_len;

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
			printf("|---------------------|-----------------------------------------------------------|-------------------------------|\n");
			printf("|%5d. %012lf  |  %s %5d    -->    %s %5d    | TCP  # %3d    %10d bytes|\n",
			 		total_ip_count, pkt_ts,
				   	ip_address_sender,src_port, ip_address_receiver,dst_port,
				   	tcp_count, pkt_len );
		}
		else if (ip_hdr->ip_p == IPPROTO_UDP)
		{
			udp_count++;
			udp_hdr = (struct udphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
			src_port = ntohs(udp_hdr->source);
			dst_port = ntohs(udp_hdr->dest);
			insert_src(ip_hdr, pkt_len, dst_port, pkt_ts, ids);
			hs_insert_port(ip_hdr, dst_port, pkt_ts, ids);
			printf("|---------------------|-----------------------------------------------------------|-------------------------------|\n");
			printf("|%5d. %012lf  |  %s %5d    -->    %s %5d    | UDP  # %3d    %10d bytes|\n",
			 		total_ip_count, pkt_ts,
				   	ip_address_sender,src_port, ip_address_receiver,dst_port,
				   	udp_count, pkt_len );
		}
		else if (ip_hdr->ip_p == IPPROTO_ICMP)
		{
			icmp_count++;  
			insert_src(ip_hdr, pkt_len, 0, pkt_ts, ids);
			hs_insert_port(ip_hdr, 0, pkt_ts, ids);
			printf("|---------------------|-----------------------------------------------------------|-------------------------------|\n");
			printf("|%5d. %012lf  |  %s %5d    -->    %s %5d    | ICMP # %3d    %10d bytes|\n",
			 		total_ip_count, pkt_ts,
				   	ip_address_sender,0, ip_address_receiver,0,
				   	icmp_count, pkt_len );
		}
	}


	//intrusion in the last epoch
	printf("\n======================================================EPOCH SUMMARY======================================================\n\n");
	report_HH_VS();
	report_HS();
	printf("\n=========================================================================================================================\n\n");
	cleanup();

	//final summary
	printf("=====================================================FINAL STATISTICS====================================================\n\n");
	printf("The total number of observed packets: %d\n", frame_count);
	printf("The total number of observed IP packets: %d\n", total_ip_count);
	printf("The total number of valid IP packets that pass the checksum test: %d\n", valid_ip_count);
	printf("The total IP payload size (valid IP packets only): %ld bytes\n", total_ip_payload);
	printf("The total number of TCP packets (valid IP packets only): %d\n", tcp_count);
	printf("The total number of UDP packets (valid IP packets only): %d\n", udp_count);
	printf("The total number of ICMP packets (valid IP packets only): %d\n\n", icmp_count);
	printf("=========================================================================================================================\n\n");

	pcap_close(pcap);

	return 0;
}