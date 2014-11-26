#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>

#include <pcap.h>
#include <pcap/sll.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "rtp.h"
#include "util.h"

int i = 1;

static uint16_t parse_en10mb(const uint8_t *packet, const uint8_t **payload)
{
    const struct ether_header *hdr = (struct ether_header *)packet;
    *payload = &packet[sizeof(*hdr)];
    return ntohs(hdr->ether_type);
}

static uint16_t parse_linux_sll(const uint8_t *packet, const uint8_t **payload)
{
    const struct sll_header *hdr = (struct sll_header *)packet;
    *payload = &packet[sizeof(*hdr)];
    return ntohs(hdr->sll_protocol);
}

void process_packet(int datalink, const uint8_t *packet, const struct pcap_pkthdr *header)
{
    uint16_t protocol = 0;
    const uint8_t *payload = NULL;
    const struct udphdr *udp = NULL;

    switch (datalink) {
    case DLT_NULL:
        printf("Don't understand DLT_NULL\n");
        break;
    case DLT_EN10MB:
        protocol = parse_en10mb(packet, &payload);
        break;
    case DLT_RAW:
        printf("Don't understand DLT_RAW\n");
        break;
    case DLT_LINUX_SLL:
        protocol = parse_linux_sll(packet, &payload);
        break;
    default:
        printf("Don't understand datalink\n");
        break;
    }

    if (protocol == ETH_P_IP) {
        const struct ip *ipheader = (const struct ip *)payload;
        if (ipheader->ip_v != IPVERSION) {
            printf("Not a ipv4 packet\n");
            return;
        }

        if (ipheader->ip_p != IPPROTO_UDP) {
            printf("Not a UDP packet\n");
            return;
        }

        udp = (struct udphdr *)&payload[ipheader->ip_hl * 4];
    } else if (protocol == ETH_P_IPV6) {
        fprintf(stderr, "not implemented yet");
        exit(1);
    } else {
        printf("protocol: 0x%x unrecognized\n", protocol);
        return;
    }

    if (udp) {
        /* printf("sport: %d\n", ntohs(udp->uh_sport)); */
        /* printf("dport: %d\n", ntohs(udp->uh_dport)); */

        const uint8_t *data = (const uint8_t *)udp;

        data += sizeof(struct udphdr);
        size_t payload_len = header->caplen - (data - packet);

        struct rtp_hdr *hdr = (struct rtp_hdr *)data;
        printf("%d: ", i++);
        describe_rtp(hdr);
        hex_dump("", data, payload_len);
    }
}
