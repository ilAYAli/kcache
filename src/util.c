#include <stdio.h>
#include <ctype.h>
#include "kcache.h"

void print_hex(void *data, size_t len, unsigned int flag)
{
    unsigned char *in = (unsigned char *)data;
    int i, j;

    if (!(flag & HEX_SKIP_TAB))
        printf("\t");

    i = 0;
    while (i < len) {
        for (j = 0; j < 16 && i + j < len; j++) {
            printf("%02x", in[i + j]);
            if (!(flag & HEX_SKIP_WS))
                printf(" ");
        }

        while (j++ < 16)
            printf("   ");

        if (!(flag & HEX_SKIP_ASCII)) {
            printf("| ");
            for (j = 0; j < 16 && i + j < len; j++)
                printf("%c", isprint(in[i + j]) ? in[i + j] : '.');
        }
        i += 16;
        if (!(flag & HEX_SKIP_NL))
            printf("\n");

        if (!(flag & HEX_SKIP_TAB))
            printf("\t");
    }

    printf("\n");
}


