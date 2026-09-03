#include "ft_nmap.h"

int resolve_hostname(char *hostname, char *ip, size_t ip_size)
{
	struct addrinfo hints;
	struct addrinfo *result;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	
	if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
		return (-1);
	if (inet_ntop(AF_INET, &((struct sockaddr_in *)result->ai_addr)->sin_addr,ip,ip_size) == NULL)
	{
		freeaddrinfo(result);
		return (-1);
	}
	freeaddrinfo(result);
	return (0);
}