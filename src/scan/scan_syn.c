#include "ft_nmap.h"

void	build_syn_packet(char *buffer, char *src_ip, char *dst_ip, int dst_port)
{
	struct iphdr	*ip;
	struct tcphdr	*tcp;
	struct pseudo_header	pseudo;
	char			pseudo_packet[4096];
	memset(buffer, 0, 4096);
	memset(pseudo_packet, 0, sizeof(pseudo_packet));
	ip = (struct iphdr *)buffer;
	tcp = (struct tcphdr *)(buffer + sizeof(struct iphdr));

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
	ip->check = 0;
	ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

	tcp->source = htons(44444);
	tcp->dest = htons(dst_port);
	tcp->seq = htonl(123456);
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->syn = 1;
	tcp->ack = 0;
	tcp->rst = 0;
	tcp->fin = 0;
	tcp->window = htons(65535);
	tcp->check = 0;
	tcp->urg_ptr = 0;

	pseudo.src = ip->saddr;
	pseudo.dst = ip->daddr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.len = htons(sizeof(struct tcphdr));
	memcpy(pseudo_packet, &pseudo, sizeof(pseudo));
	memcpy(pseudo_packet + sizeof(pseudo), tcp, sizeof(struct tcphdr));
	tcp->check = checksum((unsigned short *)pseudo_packet,sizeof(pseudo) + sizeof(struct tcphdr));
}



void	listen_syn_response(pcap_t *handle, char *ip, int port)
{
	struct pcap_pkthdr		*header;
	const u_char			*packet;
	const struct iphdr		*iph;
	const struct tcphdr		*tcp;
	struct timeval			timeout;
	fd_set					readfds;
	int						fd;
	int						res;

	printf("[SYN] Waiting for response...\n");
	fd = pcap_get_selectable_fd(handle);
	if (fd < 0)
	{
		fprintf(stderr, "[SYN] pcap_get_selectable_fd failed\n");
		return;
	}
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	res = select(fd + 1, &readfds, NULL, NULL, &timeout);
	if (res == 0)
	{
		printf("[SYN] %s:%d -> Filtered \n", ip, port);
		return;
	}
	if (res < 0)
	{
		perror("select");
		return;
	}
	res = pcap_next_ex(handle, &header, &packet);
	if (res == 0)
	{
		printf("[SYN] %s:%d -> Filtered (no response)\n", ip, port);
		return;
	}
	if (res == -1)
	{
		fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
		return;
	}
	if (res == -2)
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
	tcp = (const struct tcphdr *)(packet + 14 + (iph->ihl * 4));
	if (ntohs(tcp->source) != port)
		return;
	if (ntohs(tcp->dest) != 44444)
		return;
	if (tcp->syn && tcp->ack)
	{
		printf("[SYN] %s:%d -> Open (SYN+ACK)\n", ip, port);
		printf("[OS] Possible OS: %s\n", detect_os(iph, tcp));
		return;
	}
	if (tcp->rst)
	{
		printf("[SYN] %s:%d -> Closed (RST)\n", ip, port);
		return;
	}
	printf("[SYN] %s:%d -> Filtered (unknown response)\n", ip, port);
}



void	run_scan_syn(char *ip, int port)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*handle;

	printf("[SYN] Scanning %s:%d\n", ip, port);
	handle = pcap_open_live("enp0s3",65535,1,100,errbuf);
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
	if (send_tcp_packet(ip, port, build_syn_packet) < 0)
	{
		printf("[SYN] Failed to send packet\n");
		pcap_close(handle);
		return;
	}
	listen_syn_response(handle, ip, port);
	pcap_close(handle);
}