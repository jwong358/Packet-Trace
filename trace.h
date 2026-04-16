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
unsigned int two_bytes_ntohs(const u_char *packet1, const u_char *packet2);
unsigned int four_bytes_ntohl(const u_char *packet1, const u_char *packet2, const u_char *packet3, const u_char *packet4);
void ip_checksum(const u_char *packet);
void tcp_checksum(const u_char *packet);

#endif
