#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <pulse/simple.h>
#include <pulse/error.h>

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

#include "util.h"

static inline void pa_simple_freep(pa_simple **s) { if (*s) pa_simple_free(*s); }
#define _cleanup_pa_simple_ _cleanup_(pa_simple_freep)


static void dump_pcap(pa_simple *s, const char *filename)
{
    const uint8_t *packet;
    struct pcap_pkthdr header;
    int error, i;

    pcap_t *handle = pcap_start(filename);
    int datalink = pcap_datalink(handle);

    for (i = 1; (packet = pcap_next(handle, &header)); ++i) {
        const struct rtp_hdr *rtp = NULL;
        parse_packet(datalink, packet, &rtp);

        const uint8_t *ulaw = (const uint8_t *)rtp + sizeof(*rtp);
        size_t payload_len = header.caplen - (ulaw - packet);

        /* printf("%d: ", i); */
        /* describe_rtp(rtp); */
        /* hex_dump("", ulaw, payload_len); */

        pa_usec_t latency = pa_simple_get_latency(s, &error);
        if (latency == (pa_usec_t)-1)
            pa_err(EXIT_FAILURE, error, "pa_simple_get_latency failed");
        fprintf(stderr, " %0.0f usec latency  \r", (float)latency);

#ifdef SIMPLE
        if (pa_simple_write(s, ulaw, payload_len, &error) < 0)
            pa_err(EXIT_FAILURE, error, "pa_simple_write failed");
#else
        int16_t pcm[payload_len];
        ulaw_decode(ulaw, pcm, payload_len);

        if (pa_simple_write(s, pcm, payload_len * sizeof(int16_t), &error) < 0)
            pa_err(EXIT_FAILURE, error, "pa_simple_write failed");
#endif
    }

    pcap_close(handle);
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        fprintf(stderr, "usage: %s [files...]\n", argv[0]);
        return 1;
    }

    _cleanup_pa_simple_ pa_simple *s = NULL;
    pa_sample_spec ss = {
#ifdef SIMPLE
        .format = PA_SAMPLE_ULAW,
#else
        .format = PA_SAMPLE_S16NE,
#endif
        .rate = 8000,
        .channels = 1
    };

    int error;
    s = pa_simple_new(NULL, argv[0], PA_STREAM_PLAYBACK, NULL, "playback", &ss, NULL, NULL, &error);
    if (!s)
        pa_err(EXIT_FAILURE, error, "pa_simple_new failed");

    int i;
    for (i = 1; i < argc; ++i) {
        /* read_pcap(argv[i]); */
        dump_pcap(s, argv[i]);
    }

    if (pa_simple_drain(s, &error) < 0)
        pa_err(EXIT_FAILURE, error, "pa_simple_drain failed");

}
