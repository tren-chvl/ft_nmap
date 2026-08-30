#include "ft_nmap.h"


int add_port(t_config *cfg, int port)
{
	if (port < 1 || port > 65535)
	{
		printf("Invalid port: %d\n", port);
		return -1;
	}
	if (cfg->port_count >= MAX_PORTS)
	{
		printf("Too many ports (max %d)\n", MAX_PORTS);
		return -1;
	}
	cfg->port[cfg->port_count++] = port;
	return 0;
}

int parse_port(char *str, t_config *cfg)
{
	char *tmp = strdup(str);
	if (!tmp)   
		return -1;
	char *tok = strtok(tmp, ",");
	while(tok)
	{
		char *dash = strchr(tok, '-');
		if (dash)
		{
			*dash = '\0';
			int start = atoi(tok);
			int end = atoi(dash + 1);
			if (start > end)
			{
				printf("Invalid range: %s-%s\n", tok, dash + 1);
				free(tmp);
				return -1;
			}
			for (int p = start; p <= end; p++)
			{
				if (add_port(cfg, p) < 0)
				{
					free(tmp);
					return -1;
				}
			}
		}
		else
		{
			if (add_port(cfg, atoi(tok)) < 0)
			{
				free(tmp);
				return -1;
			}
		}
		tok = strtok(NULL, ",");
	}
	free(tmp);
	return 0;
}


int parse_scan(char *arg, t_scan *s)
{
	char *tmp = strdup(arg);
	if (!tmp)
		return -1;
	char *tok = strtok(tmp, "/,");
	while(tok)
	{
		if (!strcmp(tok, "SYN"))
			s->syn = 1;
		else if (!strcmp(tok, "NULL"))
			s->null_scan = 1;
		else if (!strcmp(tok, "FIN"))
			s->fin = 1;
		else if (!strcmp(tok, "XMAS"))
			s->xmas = 1;
		else if (!strcmp(tok, "ACK"))
			s->ack = 1;
		else if  (!strcmp(tok, "UDP"))
			s->udp = 1;
		else
		{
			printf("Unknown scan type: %s\n", tok);
			free(tmp);
			return -1;
		}
		tok = strtok(NULL, "/,");
	}
	free(tmp);
	return (0);
}

void	print_help(void)
{
	printf("Help Screen\n");
	printf("ft_nmap [OPTIONS]\n");
	printf("--help                      Print this help screen\n");
	printf("--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf("--ip ip address to scan in dot format\n");
	printf("--file File name containing IP addresses to scan\n");
	printf("--speedup [250 max] number of parallel threads to use\n");
	printf("--scan SYN/NULL/FIN/XMAS/ACK/UDP\n");	
}

int parse_arg(int argc, char *argv[], t_config *cfg)
{
	memset(cfg, 0 , sizeof(*cfg));
	int i = 1;
	while (i < argc)
	{
		if (!strcmp(argv[i], "--help"))
		{
			print_help();
			exit(0);
		}
		else if (!strcmp(argv[i], "--ip"))
		{
			if (++i >= argc)
			{
				printf("Missing value for --ip\n");
				return -1;
			}
			cfg->ip = argv[i];
		}
		else if (!strcmp(argv[i], "--file"))
		{
			if (++i >= argc)
			{
				printf("Missing value for --file\n");
				return -1;
			}
			cfg->file = argv[i];
		}
		else if (!strcmp(argv[i], "--ports"))
		{
			if (++i >= argc)
			{
				printf("Missing value for --ports\n");
				return -1;
			}
			if (parse_port(argv[i], cfg) < 0)
				return -1;
		}
		else if (!strcmp(argv[i], "--speedup"))
		{
			if (++i >= argc)
			{
				printf("Missing value for --speedup\n");
				return -1;
			}
			cfg->speedup = argv[i];
			if (cfg->speedup < 0 || cfg->speedup > MAX_THREADS)
			{
				printf("Invalid speedup (0-%d)\n", MAX_THREADS);
				return -1;
			}
		}
		else if (!strcmp(argv[i], "--scan"))
		{
			if (++i >= argc)
			{
				printf("Missing for value --scan\n");
				return -1;
			}
			if (parse_scan(argv[i], &cfg->scans) < 0)
				return -1;
		}
		else
		{
			printf("Unknown option: %s\n", argv[i]);
			return -1;
		}
		i++;
	}
	if (!cfg->ip && !cfg->file)
	{
		printf("You must specify --ip or --file\n");
		return -1;
	}
	if (cfg->port_count == 0)
	{
		for (int p = 1; p <= 1024;p++)
			cfg->port[cfg->port_count++] = p;
	}
	if (!cfg->scans.syn && !cfg->scans.null_scan && !cfg->scans.fin && !cfg->scans.xmas && !cfg->scans.ack && !cfg->scans.udp)
	{
		cfg->scans.syn = 1;
		cfg->scans.null_scan = 1;
		cfg->scans.fin = 1;
		cfg->scans.xmas = 1;
		cfg->scans.ack = 1;
		cfg->scans.udp = 1;
	}
	return 0;
}