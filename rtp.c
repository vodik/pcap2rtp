#include "rtp.h"

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

static const char *payload_types[] = {
    "PCMU", "1016",  "G721", "GSM",      "G723",  "DVI4", "DVI4", "LPC",
    "PCMA", "G722",  "L16",  "L16",      "QCELP", "CN",   "MPA",  "G728",
    "DV14", "DV14",  "G729", "reserved", NULL,    NULL,   NULL,   NULL,
    NULL,   "CellB", "JPEG", NULL,       "nv",    NULL,    NULL,  "H261",
    "MPV",  "MP2T", "H263"
};


void describe_rtp(struct rtp_hdr *hdr)
{
    const char *payload_str = NULL;

    if (hdr->rtp_ver != 2) {
        printf("not a rtp packet\n");
        return;
    }

    if (hdr->rtp_payload < 35)
        payload_str = payload_types[hdr->rtp_payload];
    else if (hdr->rtp_payload >= 96 && hdr->rtp_payload <= 127)
        payload_str = "dynamic";

    if (payload_str)
        printf("%s rtp packet", payload_str);
    else
        printf("packet with unknown protocol 0x%x\n", hdr->rtp_payload);
}

