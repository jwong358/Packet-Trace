#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "trace.h"



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
    int res;
    int packet_count = 0;
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 1) { // A packet was read successfully
            packet_count++;
            printf("Packet Number: %d, Packet length: %d\n", packet_count, header->len);
            ethernet(packet);
        } else if (res == -1) {
            fprintf(stderr, "Error reading the packet: %s\n", pcap_geterr(handle));
            break;
        } else if (res == -2) {
            printf("No more packets to read from the pcap file.\n");
            break;
        } else {
            fprintf(stderr, "Unknown error occurred while reading the packet.\n");
            break;
        }
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}

void ethernet(const u_char *packet) {
    // Process Ethernet header
    if (packet == NULL) {
        fprintf(stderr, "Null packet data received in ethernet function.\n");
        return;
    }

    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("\t\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    if (packet[12] == 0x08 && packet[13] == 0x00) {
        printf("\t\tType: IP\n");
        ip(packet);
    } else if (packet[12] == 0x08 && packet[13] == 0x06) {
        printf("\t\tType: ARP\n");
        arp(packet);
    }
}

void arp(const u_char *packet) {
    // Process ARP header
    printf("\tARP Header\n");
    if (packet[21] == 0x01) {
        printf("\t\tOpcode: Request\n");
    } else if (packet[21] == 0x02) {
        printf("\t\tOpcode: Reply\n");
    }
    printf("\t\tSender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        packet[22], packet[23], packet[24], packet[25], packet[26], packet[27]);
    printf("\t\tSender IP: %d.%d.%d.%d\n",
            strtol(packet[28], NULL, 16),
            strtol(packet[29], NULL, 16),
            strtol(packet[30], NULL, 16),
            strtol(packet[31], NULL, 16));
    printf("\t\tTarget MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
    printf("\t\tTarget IP: %d.%d.%d.%d\n",
            strtol(packet[38], NULL, 16),
            strtol(packet[39], NULL, 16),
            strtol(packet[40], NULL, 16),
            strtol(packet[41], NULL, 16));
}

void ip(const u_char *packet) {
    // Process IP header
    printf("\tIP Header\n");

    long decimal_length = strtol(packet[16] << 8 | packet[17], NULL, 16);
    printf("\t\tIP PDU len: %d\n", decimal_length);

    long decimal_header_length = strtol(packet[14] & 0x0F, NULL, 16) * 4;
    printf("\t\tHeader len (bytes): %d\n", decimal_header_length);

    long decimal_time_to_live = strtol(packet[22], NULL, 16);
    printf("\t\tTime to Live: %d\n", decimal_time_to_live);

    if (packet[23] == 0x01) {
        printf("\t\tProtocol: ICMP\n");
        printf("\t\tChecksum: %02x%02x\n", packet[24], packet[25]); // fix
        printf("\t\tSender IP: %d.%d.%d.%d\n",
                strtol(packet[26], NULL, 16),
                strtol(packet[27], NULL, 16),
                strtol(packet[28], NULL, 16),
                strtol(packet[29], NULL, 16));
        printf("\t\tDest IP: %d.%d.%d.%d\n",
                strtol(packet[30], NULL, 16),
                strtol(packet[31], NULL, 16),
                strtol(packet[32], NULL, 16),
                strtol(packet[33], NULL, 16));
        icmp(packet);
    } else if (packet[23] == 0x06) {
        printf("\t\tProtocol: TCP\n");
        printf("\t\tChecksum: %02x%02x\n", packet[24], packet[25]); // fix
        printf("\t\tSender IP: %d.%d.%d.%d\n",
                strtol(packet[26], NULL, 16),
                strtol(packet[27], NULL, 16),
                strtol(packet[28], NULL, 16),
                strtol(packet[29], NULL, 16));
        printf("\t\tDest IP: %d.%d.%d.%d\n",
                strtol(packet[30], NULL, 16),
                strtol(packet[31], NULL, 16),
                strtol(packet[32], NULL, 16),
                strtol(packet[33], NULL, 16));
        tcp(packet);
    } else if (packet[23] == 0x11) {
        printf("\t\tProtocol: UDP\n");
        printf("\t\tChecksum: %02x%02x\n", packet[24], packet[25]); // fix
        printf("\t\tSender IP: %d.%d.%d.%d\n",
                strtol(packet[26], NULL, 16),
                strtol(packet[27], NULL, 16),
                strtol(packet[28], NULL, 16),
                strtol(packet[29], NULL, 16));
        printf("\t\tDest IP: %d.%d.%d.%d\n",
                strtol(packet[30], NULL, 16),
                strtol(packet[31], NULL, 16),
                strtol(packet[32], NULL, 16),
                strtol(packet[33], NULL, 16));
        udp(packet);
    }
}

void icmp(const u_char *packet) {
    // Process ICMP header
    printf("\tICMP Header\n");
    if (packet[34] == 0x00) {
        printf("\t\tType: Reply\n");
    } else if (packet[34] == 0x08) {
        printf("\t\tType: Request\n");
    }
}

void tcp(const u_char *packet) {
    // Process TCP header
    printf("\tTCP Header\n");
    printf("\t\tSegment Length: %d\n", (strtol(packet[46] & 0xF0, NULL, 16)) * 4);
    printf("\t\tSource Port: %d\n", strtol(packet[34] << 8 | packet[35], NULL, 16));
    printf("\t\tDest Port: %d\n", strtol(packet[36] << 8 | packet[37], NULL, 16)); // fix
    printf("\t\tSequence Number: %d\n", strtol(packet[38] << 24 | packet[39] << 16 | packet[40] << 8 | packet[41], NULL, 16));
    printf("\t\tACK Number: %d\n", strtol(packet[42] << 24 | packet[43] << 16 | packet[44] << 8 | packet[45], NULL, 16));
    printf("\t\tSYN Flag: %s\n", (packet[47] & 0x02) ? "Yes" : "No");
    printf("\t\tRST Flag: %s\n", (packet[47] & 0x04) ? "Yes" : "No");
    printf("\t\tFIN Flag: %s\n", (packet[47] & 0x01) ? "Yes" : "No");
    printf("\t\tACK Flag: %s\n", (packet[47] & 0x10) ? "Yes" : "No");
    printf("\t\tWindow Size: %d\n", strtol(packet[48] << 8 | packet[49], NULL, 16));
    printf("\t\tChecksum: %02x%02x\n", packet[50], packet[51]); // fix
}

void udp(const u_char *packet) {
    // Process UDP header
    printf("\tUDP Header\n");
    printf("\t\tSource Port: %d\n", strtol(packet[34] << 8 | packet[35], NULL, 16)); // fix
    printf("\t\tDest Port: %d\n", strtol(packet[36] << 8 | packet[37], NULL, 16));
}