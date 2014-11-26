#include "rtp.h"

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

static const char *payload_types[] = {
    "PCMU", "1016",  "G721", "GSM", "G723",  "DVI4", "DVI4", "LPC",
    "PCMA", "G722",  "L16",  "L16", "QCELP", "CN",   "MPA",  "G728",
    "DV14", "DV14",  "G729", NULL,  NULL,    NULL,   NULL,   NULL,
    NULL,   "CellB", "JPEG", NULL,  "nv",    NULL,   NULL,   "H261",
    "MPV",  "MP2T",  "H263"
};


void describe_rtp(const struct rtp_hdr *rtp)
{
    if (rtp->rtp_ver != 2) {
        printf("not a rtp packet\n");
        return;
    }

    if (rtp->rtp_payload == 19 || (rtp->rtp_payload >= 72 && rtp->rtp_payload <= 76)) {
        printf("reserved protocol (%d)", rtp->rtp_payload);
    } else if (rtp->rtp_payload < 35) {
        const char *desc = payload_types[rtp->rtp_payload];

        if (desc) {
            printf("%s rtp packet", desc);
        } else {
            printf("packet with unknown protocol %d\n", rtp->rtp_payload);
        }
    } else if (rtp->rtp_payload >= 96 && rtp->rtp_payload <= 127) {
        printf("dynamic rtp packet (%d)", rtp->rtp_payload);
    }
}
