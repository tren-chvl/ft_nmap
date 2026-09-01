#include "ft_nmap.h"

void build_null_packet(char *buffer, char *src_ip, char *dst_ip, int dst_port)
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

	tcp->fin = 0;
	tcp->syn = 0;
	tcp->rst = 0;
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
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


void run_scan_null(char *ip, int port)
{
	printf("[NULL] Scanning %s:%d\n", ip, port);
	if (send_tcp_packet(ip, port, build_null_packet) < 0)
	{
		printf("[NULL] Failed to send packet\n");
		return;
	}
	listen_tcp_response(ip, port, "NULL");
}
