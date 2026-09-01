#include "ft_nmap.h"


int send_tcp_packet(char *ip, int port, void (*builder)(char *, char *, char *, int))
{
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket");
		return -1;
	}
	int one = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
	{
		perror("setsockopt IP_HDRINCL");
		close(sock);
		return -1;
	}
	char packet[4096];
	builder(packet, "10.11.200.134", ip, port);
	struct sockaddr_in dst;
	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);
	dst.sin_addr.s_addr = inet_addr(ip);
	int size = sizeof(struct iphdr) + sizeof(struct tcphdr);
	if (sendto(sock, packet, size, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
	{
		perror("sendto");
		close(sock);
		return -1;
	}
	close(sock);
	return 0;
}



void listen_tcp_response(char *ip, int port, char *scan_name)
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
		printf("[%s] %s:%d -> Open|Filtered (no response)\n", scan_name, ip, port);
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
		printf("[%s] %s:%d -> Closed (RST)\n", scan_name, ip, port);
	else
		printf("[%s] %s:%d -> Open|Filtered (unknown response)\n", scan_name, ip, port);
	pcap_close(handle);
}
