/*
 * Intrusion Detection System 
 * By Ghous Ali Khan & Atif Khurshid
 * ESTR4120 Assignment 2
 * Based on code from:
 *  	sniffer.cc
 *  	Use the libpcap library to write a sniffer.
 *   	By Patrick P. C. Lee.
 */

#include "ids.h"

struct src_host *HEAD_LIST_ONE = NULL; //list of lists for tracking HH and VS
struct hs_port *HEAD_LIST_TWO = NULL;  // list of lists for tracking HS


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

	if (HEAD_LIST_ONE == NULL) {
		HEAD_LIST_ONE = new_node;
	}
	else {

		src_host *pre_node = NULL;
		src_host *cur_node = HEAD_LIST_ONE;
		while (cur_node != NULL)
		{
			pre_node = cur_node;
			if (cur_node->src_ip == src_ip)
			{
				cur_node->data_sent += payload;

				insert_des(cur_node->targets, des_ip, port_number, pkt_ts, ids);
				if (cur_node->data_sent > ids.HH_threshold)
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

	if (payload > ids.HH_threshold)
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
	new_node->port = (des_port **) malloc(sizeof(des_port *));
	*(new_node->port) = NULL;
	new_node->next = NULL;
	new_node->des_ip = des_ip;
	new_node->port_count = 0;
	new_node->VS_ts = -1;

	if (*head == NULL) {
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
					if (cur_node->port_count > VS_threshold)
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
		if (new_node->port_count > VS_threshold)
		{
			new_node->VS_ts = pkt_ts;
		}
	}
	return;
}

//Inserts Port number (Level 3) in List One
int insert_port(struct des_port **head, uint16_t port_number)
{

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
				printf("    |--------------|--------------------|-------------------------|------------------------------|------------------|\n");

				printf("    | %012lf | HORIZONTAL SCANNER | Source: %s | Target Port: %15u | Num targets: %3d |\n", HS_ts, ip_address_sender, port_number, SRC_ptr->des_count);
							}
			SRC_ptr = SRC_ptr->next;
		}
		PORT_ptr = PORT_ptr->next;
	}
	printf("    |---------------------------------------------------------------------------------------------------------------|\n");
}
void report_HH_VS()
{
	printf("    |---------------------------------------------------INTRUSIONS--------------------------------------------------|\n");
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
			printf("    |--------------|--------------------|-------------------------|------------------------------|------------------|\n");
			printf("    | %012lf |    HEAVY HITTER    | Source: %s | Payload: %13d bytes |                  |\n",
					 pkt_ts, ip_address_sender, payload);
			
		}
		while (VS_ptr != NULL)
		{
			vs_ts = VS_ptr->VS_ts;
			if (vs_ts != -1)
			{
				src_ip = HH_ptr->src_ip;
				des_ip = VS_ptr->des_ip;

				sprintf(ip_address_sender, "%u.%u.%u.%u", src_ip & 0xff, (src_ip >> 8) & 0xff,
						(src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);
				ip_format(ip_address_sender);
				sprintf(ip_address_receiver, "%u.%u.%u.%u", des_ip & 0xff, (des_ip >> 8) & 0xff,
						(des_ip >> 16) & 0xff, (des_ip >> 24) & 0xff);
				ip_format(ip_address_receiver);
				printf("    |--------------|--------------------|-------------------------|------------------------------|------------------|\n");

				printf("    | %012lf |  VERTICAL SCANNER  | Source: %s | Target IP:   %s | Num ports: %5d |\n", 
					vs_ts, ip_address_sender, ip_address_receiver, VS_ptr->port_count);
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
	*(new_node->sources) = NULL;

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
	*(new_node->targets) = NULL;
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
					if (cur_node->des_count > ids.HS_threshold)
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

	if (new_node->des_count > ids.HS_threshold)
		new_node->HS_ts = pkt_ts;
	return;
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

unsigned short in_cksum(unsigned short* addr, int len)	// Interent checksum
{
	int nleft = len, sum = 0;
	unsigned short *w = addr, answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned char*) &answer = *(u_char*) w;
		sum += answer;
    }

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum;
}

unsigned short ip_checksum(unsigned char *iphdr)
{
	char buf[20];	// IP header size
	struct iphdr *iph;
	memcpy(buf, iphdr, sizeof(buf));
	iph = (struct iphdr *) buf;
	iph->check = 0;

	return in_cksum((unsigned short *)buf, sizeof(buf));
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


void cleanup()
{
	struct src_host *list_1_level_1 = HEAD_LIST_ONE;
	struct des_host *list_1_level_2 = NULL;
	struct des_port *list_1_level_3 = NULL; 
	struct src_host *list_1_level_1_temp = NULL;
	struct des_host *list_1_level_2_temp = NULL;
	struct des_port *list_1_level_3_temp = NULL;

	struct hs_port *list_2_level_1 = HEAD_LIST_TWO;
	struct hs_src  *list_2_level_2 = NULL;
	struct hs_des  *list_2_level_3 = NULL;
	struct hs_port *list_2_level_1_temp = NULL;
	struct hs_src  *list_2_level_2_temp = NULL;
	struct hs_des  *list_2_level_3_temp = NULL;

	HEAD_LIST_ONE = NULL;
	HEAD_LIST_TWO = NULL;

	while (list_1_level_1 != NULL)
	{
		list_1_level_1_temp = list_1_level_1;


		list_1_level_2 = *(list_1_level_1_temp->targets);
		while(list_1_level_2 != NULL)
		{
			list_1_level_2_temp = list_1_level_2;

			list_1_level_3 = *(list_1_level_2_temp->port);
			while (list_1_level_3 != NULL) {
				list_1_level_3_temp = list_1_level_3;
				list_1_level_3 = list_1_level_3->next;
				free(list_1_level_3_temp);	
			}
		    list_1_level_2 = list_1_level_2->next;
			free(list_1_level_2_temp);
		}
		list_1_level_1 = list_1_level_1->next;
		free(list_1_level_1_temp);
	}
	while (list_2_level_1 != NULL)
	{
		list_2_level_1_temp = list_2_level_1;

		list_2_level_2 = *(list_2_level_1_temp->sources);
		while(list_2_level_2 != NULL)
		{
			list_2_level_2_temp = list_2_level_2;

			list_2_level_3 = *(list_2_level_2_temp->targets);
			while (list_2_level_3 != NULL) {
				list_2_level_3_temp = list_2_level_3;
				list_2_level_3 = list_2_level_3->next;
				free(list_2_level_3_temp);	
			}
		    list_2_level_2 = list_2_level_2->next;
			free(list_2_level_2_temp);
		}
		list_2_level_1 = list_2_level_1->next;
		free(list_2_level_1_temp);
	}
}

