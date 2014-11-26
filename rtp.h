#pragma once

#include <stdint.h>
#include <asm/byteorder.h>

struct rtp_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint16_t rtp_csrc:4,
             rtp_ext:1,
             rtp_pad:1,
             rtp_ver:2,
             rtp_payload:7,
             rtp_marker:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint16_t rtp_ver:2,
             rtp_pad:1,
             rtp_ext:1,
             rtp_csrc:4,
             rtp_marker:1,
             rtp_payload:7;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    uint16_t rtp_seq;
    uint32_t rtp_timestamp;
    uint32_t rtp_ssrc;
};

void describe_rtp(const struct rtp_hdr *rtp);
