#pragma once

#include <stdint.h>
#include <pcap.h>
#include "rtp.h"

void find_rtp(const char *filename, void (*rtp_cb)(const struct rtp_hdr *rtp, size_t len));
