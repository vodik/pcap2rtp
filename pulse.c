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

#include "rtp.h"

#define _unused_        __attribute__((unused))
#define _noreturn_      __attribute__((noreturn))
#define _printf_(a,b)   __attribute__((format (printf, a, b)))
#define _cleanup_(x)    __attribute__((cleanup(x)))
#define _cleanup_free_  _cleanup_(freep)


void parse_packet(int datalink, const uint8_t *packet, const struct rtp_hdr **rtp);
pcap_t *pcap_start(const char *filename);


static inline void pa_simple_freep(pa_simple **s) { if (*s) pa_simple_free(*s); }
#define _cleanup_pa_simple_ _cleanup_(pa_simple_freep)

static void _noreturn_ _printf_(3,4) pa_err(int eval, int error, const char *fmt, ...)
{
    fprintf(stderr, "%s: ", program_invocation_short_name);

    if (fmt) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, ": ");
    }

    fprintf(stderr, "%s\n", pa_strerror(error));
    exit(eval);
}

/*{{{*/
static void mulaw_decode(const uint8_t *in, int16_t *out, size_t len) {

    static short ulaw_decompression[256] = {
        -32124,-31100,-30076,-29052,-28028,-27004,-25980,-24956,
        -23932,-22908,-21884,-20860,-19836,-18812,-17788,-16764,
        -15996,-15484,-14972,-14460,-13948,-13436,-12924,-12412,
        -11900,-11388,-10876,-10364, -9852, -9340, -8828, -8316,
        -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
        -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
        -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
        -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
        -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
        -1372, -1308, -1244, -1180, -1116, -1052,  -988,  -924,
        -876,  -844,  -812,  -780,  -748,  -716,  -684,  -652,
        -620,  -588,  -556,  -524,  -492,  -460,  -428,  -396,
        -372,  -356,  -340,  -324,  -308,  -292,  -276,  -260,
        -244,  -228,  -212,  -196,  -180,  -164,  -148,  -132,
        -120,  -112,  -104,  -96,   -88,   -80,   -72,   -64,
        -56,   -48,   -40,   -32,   -24,   -16,    -8,     -1,
        32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
        23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
        15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
        11900, 11388, 10876, 10364,  9852,  9340,  8828,  8316,
        7932,  7676,  7420,  7164,  6908,  6652,  6396,  6140,
        5884,  5628,  5372,  5116,  4860,  4604,  4348,  4092,
        3900,  3772,  3644,  3516,  3388,  3260,  3132,  3004,
        2876,  2748,  2620,  2492,  2364,  2236,  2108,  1980,
        1884,  1820,  1756,  1692,  1628,  1564,  1500,  1436,
        1372,  1308,  1244,  1180,  1116,  1052,   988,   924,
        876,   844,   812,   780,   748,   716,   684,   652,
        620,   588,   556,   524,   492,   460,   428,   396,
        372,   356,   340,   324,   308,   292,   276,   260,
        244,   228,   212,   196,   180,   164,   148,   132,
        120,   112,   104,   96,    88,    80,    72,    64,
        56,    48,    40,    32,    24,    16,     8,     0
    };

    size_t i;
    for (i = 0; i < len; ++i)
        out[i] = ulaw_decompression[in[i]];
}
/*}}}*/

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
        mulaw_decode(ulaw, pcm, payload_len);

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
