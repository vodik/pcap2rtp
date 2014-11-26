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
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "pager.h"
#include "rtp.h"
#include "util.h"

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

static void parse_packet(int datalink, const uint8_t *packet, const struct rtp_hdr **rtp)
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
        const struct ip *ipv4 = (const struct ip *)payload;

        if (ipv4->ip_v != IPVERSION) {
            printf("Not a ipv4 packet\n");
            return;
        }

        if (ipv4->ip_p != IPPROTO_UDP) {
            printf("Not a UDP packet\n");
            return;
        }

        payload += ipv4->ip_hl * 4;
        udp = (struct udphdr *)payload;
    } else if (protocol == ETH_P_IPV6) {
        fprintf(stderr, "not implemented yet");
        exit(1);
    } else {
        printf("protocol: 0x%x unrecognized\n", protocol);
        return;
    }

    *rtp = udp ? (struct rtp_hdr *)&payload[sizeof(*udp)] : NULL;
}

static pcap_t *pcap_start(const char *filename)
{
    char err[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(filename, err);
    if (!handle)
        errx(1, "couldn't open pcap file %s", filename);

    return handle;
}

static void read_pcap(const char *filename)
{
    const uint8_t *packet;
    struct pcap_pkthdr header;
    int i;

    pcap_t *handle = pcap_start(filename);
    int datalink = pcap_datalink(handle);

    for (i = 1; (packet = pcap_next(handle, &header)); ++i) {
        const struct rtp_hdr *rtp = NULL;

        parse_packet(datalink, packet, &rtp);

        size_t payload_len = header.caplen - ((const uint8_t *)rtp - packet);

        printf("%d: ", i);
        describe_rtp(rtp);
        hex_dump("", rtp, payload_len);
    }

    pcap_close(handle);
}

int main(int argc, char *argv[])
{
    int i;

    if (argc == 1) {
        fprintf(stderr, "usage: %s [files...]\n", argv[0]);
        return 1;
    }

    pid_t pager = pager_start("FRSX");

    for (i = 1; i < argc; ++i) {
        printf("Loading pcap %s...\n\n", argv[i]);
        read_pcap(argv[i]);
    }

    return pager ? pager_wait(pager) : 0;
}
