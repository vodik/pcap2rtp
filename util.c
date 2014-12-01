#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pulse/simple.h>
#include <pulse/error.h>

void hex_dump(const char *desc, const void *addr, size_t len)
{
    const unsigned char *pc = addr;
    unsigned char readable[17] = { 0 };
    size_t i;

    if (desc)
        printf("%s:\n", desc);

    for (i = 0; i < len; i++) {
        size_t mod16 = i % 16;

        if (mod16 == 0) {
            if (readable[0])
                printf("  %s\n", readable);
            printf(" %06zx:", i);
        }

        printf(i % 2 ? "%02x" : " %02x", pc[i]);

        if (pc[i] < 0x20 || pc[i] > 0x7e)
            readable[mod16] = '.';
        else
            readable[mod16] = pc[i];
        readable[mod16 + 1] = '\0';
    }

    for (; i % 16 != 0; ++i)
        printf(i % 2 ? "  " : "   ");
    printf("  %s\n", readable);
}

void _noreturn_ _printf_(3,4) pa_err(int eval, int error, const char *fmt, ...)
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
