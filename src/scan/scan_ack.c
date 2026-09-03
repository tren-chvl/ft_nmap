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

void listen_ack_response(pcap_t *handle, char *ip, int port)
{
	struct pcap_pkthdr *header;
	const u_char *packet;
	const struct iphdr *iph;
	const struct tcphdr *tcp;
	struct timeval timeout;
	fd_set readfds;
	int fd;
	int res;

	printf("[ACK] Waiting for response...\n");
	fd = pcap_get_selectable_fd(handle);
	if (fd < 0)
	{
		fprintf(stderr, "[ACK] pcap_get_selectable_fd failed\n");
		return;
	}
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	res = select(fd + 1, &readfds, NULL, NULL, &timeout);
	if (res == 0)
	{
		printf("[ACK] %s:%d -> Filtered \n", ip, port);
		return;
	}
	if (res < 0)
	{
		perror("select");
		return;
	}
	res = pcap_next_ex(handle, &header, &packet);
	if (res != 1)
		return;
	if (header->caplen < 14 + sizeof(struct iphdr))
		return;
	iph = (const struct iphdr *)(packet + 14);
	if (iph->version != 4 || iph->ihl < 5)
		return;
	if (iph->protocol != IPPROTO_TCP)
		return;
	if (header->caplen < 14 + (iph->ihl * 4) + sizeof(struct tcphdr))
		return;
	tcp = (const struct tcphdr *)(packet + 14 + iph->ihl * 4);
	if (ntohs(tcp->source) != port)
		return;
	if (ntohs(tcp->dest) != 44444)
		return;
	if (tcp->rst)
	{
		printf("[ACK] %s:%d -> Unfiltered (RST)\n", ip, port);
		return;
	}
	printf("[ACK] %s:%d -> Filtered (unknown response)\n", ip, port);
}

void run_scan_ack(char *ip, int port)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	printf("[ACK] Scanning %s:%d\n", ip, port);
	handle = pcap_open_live("wlp9s0",65535,1,100,errbuf);
	if (!handle)
	{
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		return;
	}
	if (setup_tcp_filter(handle, ip, port) < 0)
	{
		pcap_close(handle);
		return;
	}
	if (send_tcp_packet(ip, port, build_ack_packet) < 0)
	{
		printf("[ACK] Failed to send packet\n");
		pcap_close(handle);
		return;
	}
	listen_ack_response(handle, ip, port);
	pcap_close(handle);
}