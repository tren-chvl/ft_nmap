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
	builder(packet, "192.168.1.13", ip, port);
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


int setup_tcp_filter(pcap_t *handle, char *ip, int port)
{
	char					filter[256];
	struct bpf_program		fp;

	snprintf(filter ,sizeof(filter) ,"tcp and src host %s and src port %d and dst port 44444", ip, port);
	if (pcap_compile(handle,&fp,filter,1,PCAP_NETMASK_UNKNOWN) == -1)
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


void listen_tcp_response(pcap_t *handle, char *ip, int port, char *scan_name)
{
	struct pcap_pkthdr *header;
	const u_char *packet;
	struct timeval timeout;
	fd_set readfds;
	int fd;
	int res;

	printf("[%s] Waiting for response...\n", scan_name);
	fd = pcap_get_selectable_fd(handle);
	if (fd < 0)
	{
		fprintf(stderr, "pcap_get_selectable_fd failed\n");
		return ;
	}
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	res = select(fd + 1, &readfds, NULL, NULL, &timeout);
	if (res == 0)
	{
		printf("[%s] %s:%d -> Open|Filtered \n", scan_name, ip, port);
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
	const struct iphdr *iph = (const struct iphdr *)(packet + 14);
	if (iph->version != 4 || iph->ihl < 5)
		return;
	if (iph->protocol != IPPROTO_TCP)
		return;
	if (header->caplen < 14 + iph->ihl * 4 + sizeof(struct tcphdr))
		return;
	const struct tcphdr *tcp = (const struct tcphdr *)(packet + 14 + iph->ihl * 4);
	if (ntohs(tcp->source) != port)
		return;
	if (ntohs(tcp->dest) != 44444)
		return;
	if (tcp->rst)
	{
		printf("[%s] %s:%d -> Closed (RST)\n",
			scan_name, ip, port);
		return;
	}
	printf("[%s] %s:%d -> Open|Filtered (unknown response)\n", scan_name, ip, port);
}


