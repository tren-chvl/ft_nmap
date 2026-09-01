#include "ft_nmap.h"


void build_ack_packet(char *buffer, char *src_ip, char *dst_ip, int dst_port)
{
	struct iphdr *ip = (struct iphdr *)buffer;
	struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct iphdr));
	memset(buffer, 0, 4096);

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	ip->id = htons(54321);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = inet_addr(src_ip);
	ip->daddr = inet_addr(dst_ip);
	ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

	tcp->source = htons(44444);
	tcp->dest = htons(dst_port);
	tcp->seq = htonl(0);
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->ack = 1;
	tcp->window = htons(65535);
	struct pseudo_header pseudo;
	pseudo.src = ip->saddr;
	pseudo.dst = ip->daddr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.len = htons(sizeof(struct tcphdr));
	char pseudo_packet[4096];
	memcpy(pseudo_packet, &pseudo, sizeof(pseudo));
	memcpy(pseudo_packet + sizeof(pseudo), tcp, sizeof(struct tcphdr));
	tcp->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo) + sizeof(struct tcphdr));
}

void listen_ack_response(char *ip, int port)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live("enp0s3", 65535, 0, 1000, errbuf);
	if (!handle)
	{
		printf("PCAP error: %s\n", errbuf);
		return;
	}
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res = pcap_next_ex(handle, &header, &packet);
	if (res != 1)
	{
		printf("[ACK] %s:%d -> Filtered (no response)\n", ip, port);
		pcap_close(handle);
		return;
	}
	const u_char *ip_header = packet + 14;
	struct iphdr *iph = (struct iphdr *)ip_header;
	if (iph->protocol != IPPROTO_TCP)
	{
		pcap_close(handle);
		return;
	}
	struct tcphdr *tcp = (struct tcphdr *)(ip_header + iph->ihl * 4);
	if (ntohs(tcp->source) != port)
	{
		pcap_close(handle);
		return;
	}
	if (tcp->rst)
		printf("[ACK] %s:%d -> Unfiltered (RST)\n", ip, port);
	else
		printf("[ACK] %s:%d -> Filtered (unknown response)\n", ip, port);
	pcap_close(handle);
}

void run_scan_ack(char *ip, int port)
{
	printf("[ACK] Scanning %s:%d\n", ip, port);
	if (send_tcp_packet(ip, port, build_ack_packet) < 0)
	{
		printf("[ACK] Failed to send packet\n");
		return;
	}
	listen_ack_response(ip, port);
}
