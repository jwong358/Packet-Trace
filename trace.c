#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "trace.h"
#include "checksum.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Open the pcap file
    char *pcap_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file: %s\n", errbuf);
        return EXIT_FAILURE;
    }
    
    // Read and process packets using pcap_next_ex
    struct pcap_pkthdr *header;
    const u_char *packet;
    uint8_t res;
    uint16_t packet_count = 0;
    while ((res = pcap_next_ex(handle, &header, &packet)) == 1) {
        packet_count++;
        printf("Packet number: %d  Packet Len: %d\n\n", packet_count, header->len);
        ethernet(packet);
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}

void ethernet(const u_char *packet) {
    // Process Ethernet header
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("\t\tSource MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    if (packet[12] == 0x08 && packet[13] == 0x00) {
        printf("\t\tType: IP\n\n");
        ip(packet);
    } else if (packet[12] == 0x08 && packet[13] == 0x06) {
        printf("\t\tType: ARP\n\n");
        arp(packet);
    }
}

void arp(const u_char *packet) {
    // Process ARP header
    printf("\tARP header\n");

    if (packet[21] == 0x01) {
        printf("\t\tOpcode: Request\n");
    } else if (packet[21] == 0x02) {
        printf("\t\tOpcode: Reply\n");
    }

    printf("\t\tSender MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", packet[22], packet[23], packet[24], packet[25], packet[26], packet[27]);
    printf("\t\tSender IP: %u.%u.%u.%u\n", packet[28], packet[29], packet[30], packet[31]);
    printf("\t\tTarget MAC: %01x:%01x:%01x:%01x:%01x:%01x\n", packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
    printf("\t\tTarget IP: %u.%u.%u.%u\n\n", packet[38], packet[39], packet[40], packet[41]);
}

void ip(const u_char *packet) {
    // Process IP header
    printf("\tIP Header\n");

    printf("\t\tIP PDU Len: %u\n", two_bytes_ntohs(&packet[16], &packet[17]));
    printf("\t\tHeader Len (bytes): %u\n", (packet[14] & 0x0F) * 4);
    printf("\t\tTTL: %u\n", packet[22]);
    if (packet[23] == 0x01) {
        printf("\t\tProtocol: ICMP\n");
        ip_checksum(packet);
        printf("\t\tSender IP: %u.%u.%u.%u\n", packet[26], packet[27], packet[28], packet[29]);
        printf("\t\tDest IP: %u.%u.%u.%u\n\n", packet[30], packet[31], packet[32], packet[33]);
        icmp(packet);
    } else if (packet[23] == 0x06) {
        printf("\t\tProtocol: TCP\n");
        ip_checksum(packet);
        printf("\t\tSender IP: %u.%u.%u.%u\n", packet[26], packet[27], packet[28], packet[29]);
        printf("\t\tDest IP: %u.%u.%u.%u\n\n", packet[30], packet[31], packet[32], packet[33]);
        tcp(packet);
    } else if (packet[23] == 0x11) {
        printf("\t\tProtocol: UDP\n");
        ip_checksum(packet);
        printf("\t\tSender IP: %u.%u.%u.%u\n", packet[26], packet[27], packet[28], packet[29]);
        printf("\t\tDest IP: %u.%u.%u.%u\n\n", packet[30], packet[31], packet[32], packet[33]);
        udp(packet);
    }
}

void icmp(const u_char *packet) {
    // Process ICMP header
    printf("\tICMP Header\n");
    if (packet[14 + ((packet[14] & 0x0F) * 4)] == 0x00) {
        printf("\t\tType: Reply\n\n");
    } else if (packet[14 + ((packet[14] & 0x0F) * 4)] == 0x08) {
        printf("\t\tType: Request\n\n");
    }
}

void tcp(const u_char *packet) {
    // Process TCP header
    printf("\tTCP Header\n");
    printf("\t\tSegment Length: %u\n", (two_bytes_ntohs(&packet[16], &packet[17]) - (packet[14] & 0x0F) * 4));

    if (two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4)], &packet[14 + ((packet[14] & 0x0F) * 4) + 1]) == 80) {
        printf("\t\tSource Port:  HTTP\n");
    } else {
        printf("\t\tSource Port:  %u\n", two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4)], &packet[14 + ((packet[14] & 0x0F) * 4) + 1]));
    }

    if (two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4) + 2], &packet[14 + ((packet[14] & 0x0F) * 4) + 3]) == 80) {
        printf("\t\tDest Port:  HTTP\n");
    } else {
        printf("\t\tDest Port:  %u\n", two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4) + 2], &packet[14 + ((packet[14] & 0x0F) * 4) + 3]));
    }
    printf("\t\tSequence Number: %u\n", four_bytes_ntohl(&packet[14 + ((packet[14] & 0x0F) * 4) + 4], &packet[14 + ((packet[14] & 0x0F) * 4) + 5], &packet[14 + ((packet[14] & 0x0F) * 4) + 6], &packet[14 + ((packet[14] & 0x0F) * 4) + 7]));
    printf("\t\tACK Number: %u\n", four_bytes_ntohl(&packet[14 + ((packet[14] & 0x0F) * 4) + 8], &packet[14 + ((packet[14] & 0x0F) * 4) + 9], &packet[14 + ((packet[14] & 0x0F) * 4) + 10], &packet[14 + ((packet[14] & 0x0F) * 4) + 11]));
    printf("\t\tSYN Flag: %s\n", (packet[14 + ((packet[14] & 0x0F) * 4) + 13] & 0x02) ? "Yes" : "No");
    printf("\t\tRST Flag: %s\n", (packet[14 + ((packet[14] & 0x0F) * 4) + 13] & 0x04) ? "Yes" : "No");
    printf("\t\tFIN Flag: %s\n", (packet[14 + ((packet[14] & 0x0F) * 4) + 13] & 0x01) ? "Yes" : "No");
    printf("\t\tACK Flag: %s\n", (packet[14 + ((packet[14] & 0x0F) * 4) + 13] & 0x10) ? "Yes" : "No");
    printf("\t\tWindow Size: %u\n", two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4) + 14], &packet[14 + ((packet[14] & 0x0F) * 4) + 15]));
    tcp_checksum(packet);
    printf("\n");
}

void udp(const u_char *packet) {
    // Process UDP header
    printf("\tUDP Header\n");
    if (two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4)], &packet[14 + ((packet[14] & 0x0F) * 4) + 1]) == 53) {
        printf("\t\tSource Port:  DNS\n");
    } else {
        printf("\t\tSource Port:  %u\n", two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4)], &packet[14 + ((packet[14] & 0x0F) * 4) + 1]));
    }

    if (two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4) + 2], &packet[14 + ((packet[14] & 0x0F) * 4) + 3]) == 53) {
        printf("\t\tDest Port:  DNS\n");
    } else {
        printf("\t\tDest Port:  %u\n\n", two_bytes_ntohs(&packet[14 + ((packet[14] & 0x0F) * 4) + 2], &packet[14 + ((packet[14] & 0x0F) * 4) + 3]));
    }
}

/* HELPER FUNCTIONS */

unsigned int two_bytes_ntohs(const u_char *packet1, const u_char *packet2) {
    unsigned char bytes[2] = {*packet1, *packet2};
    uint16_t network_val;

    memcpy(&network_val, bytes, sizeof(network_val));

    uint16_t host_val = ntohs(network_val);
    return host_val;
}

unsigned int four_bytes_ntohl(const u_char *packet1, const u_char *packet2, const u_char *packet3, const u_char *packet4) {
    unsigned char bytes[4] = {*packet1, *packet2, *packet3, *packet4};
    uint32_t network_val;

    memcpy(&network_val, bytes, sizeof(network_val));

    uint32_t host_val = ntohl(network_val);
    return host_val;
}

void ip_checksum(const u_char *packet) {
    u_short checksum = in_cksum((unsigned short *)(packet + 14), (packet[14] & 0x0F) * 4);
    if (checksum == 0) {
        printf("\t\tChecksum: Correct (0x%02x%02x)\n", packet[24], packet[25]);
    } else {
        printf("\t\tChecksum: Incorrect (0x%02x%02x)\n", packet[24], packet[25]);
    }
}

void tcp_checksum(const u_char *packet) {
    const u_char *ip_hdr = packet + 14;
    const u_char *tcp_seg = packet + 14 + (packet[14] & 0x0F) * 4;

    int buf_len = 12 + two_bytes_ntohs(&packet[16], &packet[17]) - (packet[14] & 0x0F) * 4;
    u_char *buf = malloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "malloc failed in tcp_checksum\n");
        return;
    }

    /* Build pseudo header */
    /* source IP */
    memcpy(buf,     ip_hdr + 12, 4);   // buf[0..3] = source IP
    /* dest IP */ 
    memcpy(buf + 4, ip_hdr + 16, 4);   // buf[4..7] = dest IP
    /* zero */
    buf[8] = 0x00;                     // buf[8] = zero
    /* protocol */
    buf[9] = ip_hdr[9];                // buf[9] = protocol (TCP is 6)    

    /* TCP length */
    uint16_t tcp_len_net = htons((uint16_t)two_bytes_ntohs(&packet[16], &packet[17]) - (packet[14] & 0x0F) * 4);
    memcpy(buf + 10, &tcp_len_net, 2); // buf[10..11] = TCP length in network byte order

    /* Copy TCP header + data */
    memcpy(buf + 12, tcp_seg, two_bytes_ntohs(&packet[16], &packet[17]) - (packet[14] & 0x0F) * 4); // buf[12..] = TCP header + data

    u_short checksum = in_cksum((unsigned short *)buf, buf_len);

    if (checksum == 0) {
        printf("\t\tChecksum: Correct (0x%02x%02x)\n",
               tcp_seg[16], tcp_seg[17]);
    } else {
        printf("\t\tChecksum: Incorrect (0x%02x%02x)\n",
               tcp_seg[16], tcp_seg[17]);
    }

    free(buf);
}