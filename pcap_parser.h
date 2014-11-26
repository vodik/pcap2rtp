#pragma once

#include <pcap.h>

void process_packet(int datalink, const uint8_t *packet, const struct pcap_pkthdr *header);
