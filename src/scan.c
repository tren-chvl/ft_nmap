#include "ft_nmap.h"

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

