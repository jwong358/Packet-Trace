#ifndef TRACE_H
#define TRACE_H

#include <pcap.h>

int main(int argc, char *argv[]);
void ethernet(const u_char *packet);
void arp(const u_char *packet);
void ip(const u_char *packet);
void icmp(const u_char *packet);
void tcp(const u_char *packet);
void udp(const u_char *packet);

#endif