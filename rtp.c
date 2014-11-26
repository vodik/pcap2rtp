#include "rtp.h"

#include <stdlib.h>
#include <stdio.h>

void describe_rtp(struct rtp_hdr *hdr)
{
    if (hdr->rtp_ver != 2) {
        printf("not a rtp packet\n");
        return;
    }

    const char *payload_str;

    switch (hdr->rtp_payload) {
    case 0:
        payload_str = "PCMU";
        break;
    case 1:
        payload_str = "1016";
        break;
    case 2:
        payload_str = "G721";
        break;
    case 3:
        payload_str = "GSM";
        break;
    case 4:
        payload_str = "G723";
        break;
    case 5:
    case 6:
        payload_str = "DVI4";
        break;
    case 7:
        payload_str = "LPC";
        break;
    case 8:
        payload_str = "PCMA";
        break;
    case 9:
        payload_str = "G722";
        break;
    case 10:
    case 11:
        payload_str = "L16";
        break;
    case 12:
        payload_str = "QCELP";
        break;
    case 13:
        payload_str = "CN";
        break;
    case 14:
        payload_str = "MPA";
        break;
    case 15:
        payload_str = "G728";
        break;
    case 16:
    case 17:
        payload_str = "DV14";
        break;
    case 18:
        payload_str = "G729";
        break;
    case 19:
        payload_str = "reserved";
        break;
    case 25:
        payload_str = "CellB";
        break;
    case 26:
        payload_str = "JPEG";
        break;
    case 28:
        payload_str = "nv";
        break;
    case 31:
        payload_str = "H261";
        break;
    case 32:
        payload_str = "MPV";
        break;
    case 33:
        payload_str = "MP2T";
        break;
    case 34:
        payload_str = "H263";
        break;
    default:
        payload_str = "unknown";
        break;
    }

    printf("%s rtp packet", payload_str);
}

