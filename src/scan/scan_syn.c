#include "ft_nmap.h"

void build_syn_packet(char *buffer,char *src_ip, char *dst_ip, int dst_port)
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

	tcp->source = htons(44444);
	tcp->dest = htons(dst_port);
	tcp->seq = htonl(0);
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->syn = 1;
	tcp->window = htons(65535);
}

int send_syn(char *ip, int port)
{
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
	{
		perror("socket");
		return -1;
	}

	char packet[4096];
	build_syn_packet(packet, "192.168.1.100", ip, port);
	struct sockaddr_in dst;
	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);
	dst.sin_addr.s_addr = inet_addr(ip);
	if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
	{
		perror("sendto");
		close(sock);
		return -1;
	}
	close(sock);
	return 0;
}

void listen_syn_response(const char *ip, int port)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live("eth0", 65535, 0, PCAP_TIMEOUT, errbuf);

	if (!handle)
	{
		printf("PCAP error: %s\n", errbuf);
		return;
	}
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res = pcap_next_ex(handle, &header, &packet);
	if (res == 1)
	{
		printf("[SYN] Received response for %s:%d\n", ip, port);
		// TODO: analyser TCP flags (SYN+ACK, RST, etc.)
	}
	else
	{
		printf("[SYN] No response for %s:%d -> Filtered\n", ip, port);
	}
	pcap_close(handle);
}

void run_scan_syn(char *ip, int port)
{
	printf("[SYN] Scanning %s:%d\n", ip, port);

	if (send_syn(ip, port) < 0)
	{
		printf("[SYN] Failed to send packet\n");
		return;
	}
	listen_syn_response(ip, port);
}
