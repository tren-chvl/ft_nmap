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


void listen_udp_response(pcap_t *handle, char *ip, int port)
{
	struct pcap_pkthdr *header;
	const u_char *packet;
	const struct iphdr *iph;
	const struct icmphdr *icmp;
	struct timeval timeout;
	fd_set readfds;
	int fd;
	int res;

	printf("[UDP] Waiting for response...\n");
	fd = pcap_get_selectable_fd(handle);
	if (fd < 0)
	{
		fprintf(stderr, "[UDP] pcap_get_selectable_fd failed\n");
		return;
	}
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	res = select(fd + 1, &readfds, NULL, NULL, &timeout);
	if (res == 0)
	{
		printf("[UDP] %s:%d -> Open|Filtered\n",ip, port);
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
	if (iph->protocol != IPPROTO_ICMP)
		return;
	if (header->caplen < 14 + iph->ihl * 4 + sizeof(struct icmphdr))
		return;
	icmp = (const struct icmphdr *)(packet + 14 + iph->ihl * 4);
	if (icmp->type == 3 && icmp->code == 3)
	{
		printf("[UDP] %s:%d -> Closed (ICMP Port Unreachable)\n",ip, port);
		return;
	}
	if (icmp->type == 3)
	{
		printf("[UDP] %s:%d -> Filtered (ICMP type 3 code %d)\n", ip, port, icmp->code);
		return;
	}
	printf("[UDP] %s:%d -> Open|Filtered (unknown ICMP)\n",ip, port);
}


int setup_icmp_filter(pcap_t *handle)
{
	struct bpf_program fp;

	if (pcap_compile(handle, &fp, "icmp", 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
		return (-1);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
		pcap_freecode(&fp);
		return (-1);
	}
	pcap_freecode(&fp);
	return (0);
}


void run_scan_udp(char *ip, int port)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	printf("[UDP] Scanning %s:%d\n", ip, port);
	handle = pcap_open_live("enp0s3",65535,1,100,errbuf);
	if (!handle)
	{
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		return;
	}
	if (setup_icmp_filter(handle) < 0)
	{
		pcap_close(handle);
		return;
	}
	if (send_udp_packet(ip, port, build_udp_packet) < 0)
	{
		printf("[UDP] Failed to send packet\n");
		pcap_close(handle);
		return;
	}
	listen_udp_response(handle, ip, port);
	pcap_close(handle);
}