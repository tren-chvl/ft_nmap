#include "ft_nmap.h"

char *detect_os(struct iphdr *ip, struct tcphdr *tcp)
{
	int ttl;
	int window;

	ttl = ip->ttl;
	window = ntohs(tcp->window);
	if (ttl <= 64)
	{
		if (window == 64240 || window == 65535)
			return ("Linux");
		return ("Linux/Unix");
	}
	if (ttl <= 128)
	{
		return ("Windows");
	}
	if (ttl <= 255)
	{
		if (window == 65535)
			return ("BSD/macOS");
	}
	return ("Unknown");
}