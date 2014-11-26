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

#include "pcap_parser.h"
#include "pager.h"

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
    pcap_t *handle;
    const uint8_t *packet;
    struct pcap_pkthdr header;

    handle = pcap_start(filename);

    int datalink = pcap_datalink(handle);

    while ((packet = pcap_next(handle, &header))) {
        process_packet(datalink, packet, &header);
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

    for (i = 1; i < argc; ++i)
        read_pcap(argv[i]);

    return pager ? pager_wait(pager) : 0;
}
