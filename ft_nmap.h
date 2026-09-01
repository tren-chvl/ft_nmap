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
#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#define MAX_PORTS 1024
#define MAX_THREADS 250
#define PCAP_TIMEOUT 1000


struct pseudo_header
{
	unsigned int src;
	unsigned int dst;
	unsigned char zero;
	unsigned char proto;
	unsigned short len;
};

typedef struct s_scans
{
	int syn;
	int null_scan;
	int fin;
	int xmas;
	int ack;
	int udp;
}   t_scan;

typedef struct s_job
{
	char *ip;
	int port;
	t_scan scans;
}	t_job;

typedef struct s_list_j
{
	t_job	*jobs;
	int		count;
	int		index;
	pthread_mutex_t thread;
}	t_list_j;

typedef struct s_config
{
	int port[MAX_PORTS];
	int port_count;
	char *ip;
	char *file;
	int speedup;
	t_scan scans;
}	t_config;

int			parse_arg(int argc, char *argv[], t_config *cfg);
void		print_help(void);
t_list_j	*create_list_job(t_config *cfg);
t_job		*get_next_job(t_list_j *lst);
void		*run_thread(void *ptr);
void		run_scan(t_job *job);
void		run_scan_syn(char *ip, int port);
void		run_scan_null(char *ip, int port);
void		run_scan_fin(char *ip, int port);
void		run_scan_xmas(char *ip, int port);
void		run_scan_ack(char *ip, int port);
void		run_scan_udp(char *ip, int port);
void		build_fin_packet(char *buffer, char *src_ip, char *dst_ip, int dst_port);
void		build_null_packet(char *buffer,char *src_ip,char *dst_ip, int dst_port);
void		build_xmas_packet(char *buffer, char *src_ip, char *dst_ip, int dst_port);
void		listen_tcp_response(char *ip, int port, char *scan_name);
unsigned short	checksum(unsigned short *ptr, int nbytes);
int			send_tcp_packet(char *ip, int port, void (*builder)(char *, char *, char *, int));
#endif