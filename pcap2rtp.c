#include <stdlib.h>
#include <stdio.h>

#include "parser.h"
#include "rtp.h"
#include "pager.h"
#include "util.h"

static void dump_rtp(const struct rtp_hdr *rtp, size_t len)
{
    static int i = 1;

    printf("%d: ", i++);
    describe_rtp(rtp);
    hex_dump("", rtp, len);
}

int main(int argc, char *argv[])
{
    int i;

    if (argc == 1) {
        fprintf(stderr, "usage: %s [files...]\n", argv[0]);
        return 1;
    }

    pid_t pager = pager_start("FRSX");

    for (i = 1; i < argc; ++i) {
        find_rtp(argv[i], &dump_rtp);
    }

    return pager ? pager_wait(pager) : 0;
}
