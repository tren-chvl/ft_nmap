#include "ft_nmap.h"


void apply_evasion(char *packet)
{
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    int ttl_values[] = {32, 64, 128, 255};
    ip->ttl = ttl_values[rand() % 4];

    int delay_us = (rand() % 20000);
    usleep(delay_us);

    tcp->window = htons(1024 + (rand() % 60000));

    tcp->source = htons(40000 + (rand() % 2000));

    struct pseudo_header pseudo;
    pseudo.src = ip->saddr;
    pseudo.dst = ip->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(sizeof(struct tcphdr));

    char pseudo_packet[4096];
    memcpy(pseudo_packet, &pseudo, sizeof(pseudo));
    memcpy(pseudo_packet + sizeof(pseudo), tcp, sizeof(struct tcphdr));
    tcp->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo) + sizeof(struct tcphdr));

    ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));
}
