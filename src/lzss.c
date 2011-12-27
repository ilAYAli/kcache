#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#define N           4096
#define F           18
#define THRESHOLD   2
#define NIL         N

unsigned char text_buf[N + F - 1];
int lson[N + 1];
int rson[N + 257];
int dad[N + 1];

void init_tree(int *rson, int *dad)
{
    int  i;

    for (i = N + 1; i <= N + 256; i++)
        rson[i] = NIL;

    for (i = 0; i < N; i++)
        dad[i] = NIL;
}

void insert_node(int r, int *match_pos, int *match_len)
{
    int  i, p, cmp;
    unsigned char  *key;

    cmp = 1;
    key = &text_buf[r];
    p = N + 1 + key[0];
    rson[r] = lson[r] = NIL;
    *match_len = 0;

    for (;;) {
        if (cmp >= 0) {
            if (rson[p] != NIL) p = rson[p];
            else {
                rson[p] = r;
                dad[r] = p;
                return;
            }
        } else {
            if (lson[p] != NIL)
                p = lson[p];
            else {
                lson[p] = r;
                dad[r] = p;
                return;
            }
        }

        for (i = 1; i < F; i++)
            if ((cmp = key[i] - text_buf[p + i]) != 0)
                break;

        if (i > *match_len) {
            *match_pos = p;

            if ((*match_len = i) >= F)
                break;
        }
    }

    dad[r] = dad[p];
    lson[r] = lson[p];
    rson[r] = rson[p];
    dad[lson[p]] = r;
    dad[rson[p]] = r;

    if (rson[dad[p]] == p)
        rson[dad[p]] = r;
    else
        lson[dad[p]] = r;

    dad[p] = NIL;
}

void delete_node(int p) 
{
    int  q;

    if (dad[p] == NIL)
        return;

    if (rson[p] == NIL)
        q = lson[p];
    else if (lson[p] == NIL)
        q = rson[p];
    else {
        q = lson[p];

        if (rson[q] != NIL) {
            do {
                q = rson[q];
            } while (rson[q] != NIL);

            rson[dad[q]] = lson[q];
            dad[lson[q]] = dad[q];
            lson[q] = lson[p];
            dad[lson[p]] = q;
        }

        rson[q] = rson[p];
        dad[rson[p]] = q;
    }

    dad[q] = dad[p];

    if (rson[dad[p]] == p)
        rson[dad[p]] = q;
    else
        lson[dad[p]] = q;

    dad[p] = NIL;
}

void lzss_compress(unsigned char *in, unsigned int len, FILE *outfile)
{
    int i, c, size, r, s, last_match_sizegth, code_buf_ptr;
    unsigned char code_buf[17], mask;
    unsigned int textsize;
    unsigned int codesize;
    int match_pos;
    int match_size;
    int idx;

    textsize = 0;
    codesize = 0;
    match_pos = 0;
    match_size = 0;
    idx = 0;

    init_tree(rson, dad);
    code_buf[0] = 0;

    code_buf_ptr = mask = 1;
    s = 0;
    r = N - F;

    for (i = 0; i < r; i++)
        text_buf[i] = ' ';

    for (size = 0; size < F; size++) {
        c = in[idx++];
        if (idx > len)
            break;
        text_buf[r + size] = c;
    }

    if (!(textsize = size))
        return; 

    for (i = 1; i <= F; i++)
        insert_node(r - i, &match_pos, &match_size);

    insert_node(r, &match_pos, &match_size); 

    do {
        if (match_size > size)
            match_size = size; 

        if (match_size <= THRESHOLD) {
            match_size = 1; 
            code_buf[0] |= mask;
            code_buf[code_buf_ptr++] = text_buf[r];
        } else {
            code_buf[code_buf_ptr++] = (unsigned char) match_pos;
            code_buf[code_buf_ptr++] = (unsigned char) (((match_pos >> 4) & 0xf0) | (match_size - (THRESHOLD + 1)));
        }

        if ((mask <<= 1) == 0) {
            for (i = 0; i < code_buf_ptr; i++) 
                putc(code_buf[i], outfile);

            codesize += code_buf_ptr;
            code_buf[0] = 0;
            code_buf_ptr = mask = 1;
        }

        last_match_sizegth = match_size;

        for (i = 0; i < last_match_sizegth; i++) {
            c = in[idx++];
            //if (idx > size)
            if (idx > len)
                break;

            delete_node(s);
            text_buf[s] = c;

            if (s < F - 1)
                text_buf[s + N] = c;

            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            insert_node(r, &match_pos, &match_size);
        }

        while (i++ < last_match_sizegth) {
            delete_node(s);
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);

            if (--size)
                insert_node(r, &match_pos, &match_size);
        }
    } while (size > 0);

    if (code_buf_ptr > 1) {
        for (i = 0; i < code_buf_ptr; i++)
            putc(code_buf[i], outfile);
        codesize += code_buf_ptr;
    }
}

void lzss_compress_org(FILE *infile, FILE *outfile)
{
    int i, c, len, r, s, last_match_length, code_buf_ptr;
    unsigned char code_buf[17], mask;
    unsigned int textsize;
    unsigned int codesize;
    int match_pos;
    int match_len;

    textsize = 0;
    codesize = 0;
    match_pos = 0;
    match_len = 0;

    init_tree(rson, dad);
    code_buf[0] = 0;

    code_buf_ptr = mask = 1;
    s = 0;
    r = N - F;

    for (i = s; i < r; i++)
        text_buf[i] = ' ';

    for (len = 0; len < F && (c = getc(infile)) != EOF; len++)
        text_buf[r + len] = c;

    if ((textsize = len) == 0)
        return; 

    for (i = 1; i <= F; i++)
        insert_node(r - i, &match_pos, &match_len);

    insert_node(r, &match_pos, &match_len); 

    do {
        if (match_len > len)
            match_len = len; 

        if (match_len <= THRESHOLD) {
            match_len = 1; 
            code_buf[0] |= mask;
            code_buf[code_buf_ptr++] = text_buf[r];
        } else {
            code_buf[code_buf_ptr++] = (unsigned char) match_pos;
            code_buf[code_buf_ptr++] = (unsigned char) (((match_pos >> 4) & 0xf0) | (match_len - (THRESHOLD + 1)));
        }

        if ((mask <<= 1) == 0) { 
            for (i = 0; i < code_buf_ptr; i++) 
                putc(code_buf[i], outfile);

            codesize += code_buf_ptr;
            code_buf[0] = 0;
            code_buf_ptr = mask = 1;
        }

        last_match_length = match_len;

        for (i = 0; i < last_match_length &&
                (c = getc(infile)) != EOF; i++) {
            delete_node(s);
            text_buf[s] = c;

            if (s < F - 1)
                text_buf[s + N] = c;

            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            insert_node(r, &match_pos, &match_len);
        }

        while (i++ < last_match_length) {
            delete_node(s);
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);

            if (--len)
                insert_node(r, &match_pos, &match_len);
        }
    } while (len > 0);

    if (code_buf_ptr > 1) {
        for (i = 0; i < code_buf_ptr; i++)
            putc(code_buf[i], outfile);

        codesize += code_buf_ptr;
    }

#ifdef PROGRESS
    printf("In : %ld bytes\n", textsize);
    printf("Out: %ld bytes\n", codesize);
    printf("Out/In: %.3f\n", (double)codesize / textsize);
#endif
}


void lzss_uncompress(unsigned char *in, unsigned int len, FILE *outfile)
{
    int i, j, k, r, c;
    unsigned int flags;
    int idx;

    for (i = 0; i < N - F; i++)
        text_buf[i] = ' ';

    r = N - F;
    flags = 0;
    idx = 0;
    while (idx < len) {
        if (!((flags >>= 1) & 256)) {
            c = in[idx++];
            if (idx >= len)
                break;
            flags = c | 0xff00;
        }

        if (flags & 1) {
            c = in[idx++];
            putc(c, outfile);
            text_buf[r++] = c;
            r &= (N - 1);
            continue;
        } 

        i = in[idx++];
        if (idx >= len)
            break;

        j = in[idx++];

        i |= ((j & 0xf0) << 4);
        j = (j & 0x0f) + THRESHOLD;

        for (k = 0; k <= j; k++) {
            c = text_buf[(i + k) & (N - 1)];
            putc(c, outfile);
            text_buf[r++] = c;
            r &= (N - 1);
        }
    }
}

