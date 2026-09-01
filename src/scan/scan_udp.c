#include "ft_nmap.h"


void build_udp_packet(char *buffer, char *src_ip, char *dst_ip, int dst_port)
{
	struct iphdr *ip = (struct iphdr *)buffer;
	struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct iphdr));
	memset(buffer, 0, 4096);

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
	ip->id = htons(54321);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = inet_addr(src_ip);
	ip->daddr = inet_addr(dst_ip);
	ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

	udp->source = htons(44444);
	udp->dest = htons(dst_port);
	udp->len = htons(sizeof(struct udphdr));
	udp->check = 0;
	struct pseudo_header pseudo;
	pseudo.src = ip->saddr;
	pseudo.dst = ip->daddr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_UDP;
	pseudo.len = udp->len;
	char pseudo_packet[4096];
	memcpy(pseudo_packet, &pseudo, sizeof(pseudo));
	memcpy(pseudo_packet + sizeof(pseudo), udp, sizeof(struct udphdr));
	udp->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo) + sizeof(struct udphdr));
}


int send_udp_packet(char *ip, int port, void (*builder)(char *, char *, char *, int))
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
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
    int size = sizeof(struct iphdr) + sizeof(struct udphdr);
    if (sendto(sock, packet, size, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
    {
        perror("sendto");
        close(sock);
        return -1;
    }
    close(sock);
    return 0;
}


void listen_udp_response(char *ip, int port)
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
		printf("[UDP] %s:%d -> Open|Filtered (no response)\n", ip, port);
		pcap_close(handle);
		return;
	}
	const u_char *ip_header = packet + 14;
	struct iphdr *iph = (struct iphdr *)ip_header;
	if (iph->protocol != IPPROTO_ICMP)
	{
		pcap_close(handle);
		return;
	}
	struct icmphdr *icmp = (struct icmphdr *)(ip_header + iph->ihl * 4);
	if (icmp->type == 3 && icmp->code == 3)
		printf("[UDP] %s:%d -> Closed (ICMP Port Unreachable)\n", ip, port);
	else if (icmp->type == 3)
		printf("[UDP] %s:%d -> Filtered (ICMP type 3 code %d)\n", ip, port, icmp->code);
	else
		printf("[UDP] %s:%d -> Open|Filtered (unknown ICMP)\n", ip, port);
	pcap_close(handle);
}


void run_scan_udp(char *ip, int port)
{
	printf("[UDP] Scanning %s:%d\n", ip, port);
	if (send_udp_packet(ip, port, build_udp_packet) < 0)
	{
		printf("[UDP] Failed to send packet\n");
		return;
	}
	listen_udp_response(ip, port);
}
