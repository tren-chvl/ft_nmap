#ifndef FT_NMAP_H
#define FT_NMAP_H


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


#define MAX_PORTS 1024
#define MAX_THREADS 250


typedef struct s_scans
{
	int syn;
	int null_scan;
	int fin;
	int xmas;
	int ack;
	int udp;
}   t_scan;


typedef struct s_config
{
	int port[MAX_PORTS];
	int port_count;
	char *ip;
	char *file;
	int speedup;
	t_scan scans;
}	t_config;

int		parse_arg(int argc, char *argv[], t_config *cfg);
void	print_help(void);

#endif