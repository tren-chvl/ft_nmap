#include "ft_nmap.h"

void print_scan(t_scan *s)
{
	printf("Scan to be perfomed : ");
	if (s->syn)
		printf("SYN ");
	if (s->null_scan)
		printf("NULL ");
	if (s->fin)
		printf("FIN ");
	if (s->xmas)
		printf("XMAS ");
	if (s->ack)
		printf("ACK ");
	if (s->udp)
		printf("UDP ");
	printf("\n");
}

void print_config(t_config *cfg)
{
	printf("Scan Configurations\n");
	if (cfg->ip)
		printf("Target Ip-Address : %s\n", cfg->ip);
	else
		printf("Target File       : %s\n", cfg->file);
	printf("No of Ports to scan   : %d\n", cfg->port_count);
	print_scan(&cfg->scans);
	printf("No of threads         : %d\n", cfg->speedup);
}

int main(int argc, char *argv[])
{
	t_config cfg;
	if (parse_arg(argc, argv, &cfg) < 0)
	{
		printf("Error: invalid arguments\n");
		return 1;
	}
	print_config(&cfg);
	printf("Scanning..\n");
	return (0);
}