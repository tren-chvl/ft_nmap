#include "ft_nmap.h"

unsigned short checksum(unsigned short *ptr, int nbytes)
{
	long sum;
	unsigned short oddbyte;
	short answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

void run_scan(t_job *job)
{
	if (job->scans.syn)
		run_scan_syn(job->ip, job->port);
	if (job->scans.null_scan)
		run_scan_null(job->ip, job->port);
	if (job->scans.fin)
		run_scan_fin(job->ip, job->port);
	if (job->scans.xmas)
		run_scan_xmas(job->ip, job->port);
	if (job->scans.ack)
		run_scan_ack(job->ip, job->port);
	if (job->scans.udp)
		run_scan_udp(job->ip, job->port);
}

