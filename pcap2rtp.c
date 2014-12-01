#include <stdlib.h>
#include <stdio.h>
#include <pulse/simple.h>
#include <pulse/error.h>

#include "parser.h"
#include "rtp.h"
#include "pager.h"
#include "util.h"

pa_simple *s = NULL;

static void dump_rtp(const struct rtp_hdr *rtp, size_t len)
{
    static int i = 1;

    printf("%d: ", i++);
    describe_rtp(rtp);
    hex_dump("", rtp, len);
}

static int dump_pcap(const char *filename)
{
    pid_t pager = pager_start("FRSX");
    find_rtp(filename, &dump_rtp);
    return pager ? pager_wait(pager) : 0;
}

static void play_rtp(const struct rtp_hdr *rtp, size_t len)
{
    int error;
    const uint8_t *ulaw = (const uint8_t *)rtp + sizeof(*rtp);

    len -= sizeof(*rtp);

    pa_usec_t latency = pa_simple_get_latency(s, &error);
    if (latency == (pa_usec_t)-1)
        pa_err(EXIT_FAILURE, error, "pa_simple_get_latency failed");
    fprintf(stderr, " %0.0f usec latency  \r", (float)latency);

    int16_t pcm[len];
    ulaw_decode(ulaw, pcm, len);

    if (pa_simple_write(s, pcm, len * sizeof(int16_t), &error) < 0)
        pa_err(EXIT_FAILURE, error, "pa_simple_write failed");
}

static int play_pcap(const char *filename)
{
    pa_sample_spec ss = {
        .format = PA_SAMPLE_S16NE,
        .rate = 8000,
        .channels = 1
    };

    int error;
    s = pa_simple_new(NULL, "pcap2rtp", PA_STREAM_PLAYBACK, NULL, "playback", &ss, NULL, NULL, &error);
    if (!s)
        pa_err(EXIT_FAILURE, error, "pa_simple_new failed");

    find_rtp(filename, play_rtp);
    printf("\n");

    if (pa_simple_drain(s, &error) < 0)
        pa_err(EXIT_FAILURE, error, "pa_simple_drain failed");

    return 0;
}

int main(int argc, char *argv[])
{
    const char *command = argv[1];
    const char *filename = argv[2];

    if (argc != 3) {
        fprintf(stderr, "usage: %s <command> [files]\n", argv[0]);
        return 1;
    }

    if (streq(command, "dump"))
        return dump_pcap(filename);
    else if (streq(command, "play"))
        return play_pcap(filename);
    else
        printf("didn't understand command '%s'\n", command);

    return 1;
}
