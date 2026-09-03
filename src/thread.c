#include "ft_nmap.h"

t_list_j *create_list_job(t_config *cfg)
{
	t_list_j *lst = malloc(sizeof(t_list_j));
	if (!lst)
		return NULL;
	lst->jobs = malloc(sizeof(t_job) * cfg->port_count);
	if (!lst->jobs)
		return NULL;
	lst->count = cfg->port_count;
	lst->index = 0;
	pthread_mutex_init(&lst->thread, NULL);
	for (int i = 0; i < cfg->port_count; i++)
	{
		lst->jobs[i].ip = cfg->ip;
		lst->jobs[i].port = cfg->port[i];
		lst->jobs[i].scans = cfg->scans;
		lst->jobs[i].os_detect = cfg->os_detect;
	}
	return lst;
}

t_job *get_next_job(t_list_j *lst)
{
	pthread_mutex_lock(&lst->thread);
	if (lst->index >= lst->count)
	{
		pthread_mutex_unlock(&lst->thread);
		return NULL;
	}
	t_job *job = &lst->jobs[lst->index];
	lst->index++;
	pthread_mutex_unlock(&lst->thread);
	return job;
}

void *run_thread(void *ptr)
{
	t_list_j *lst = (t_list_j *)ptr;
	while(1)
	{
		t_job *job = get_next_job(lst);
		if (!job)
			break;
		run_scan(job);
	}
	return NULL;
}

