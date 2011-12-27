#ifndef KCACHE_H
#define KCACHE_H

//---[ macros: ]----------------------------------------------------------------
#define TOI(a) (a[0]<<24|a[1]<<16|a[2]<<8|a[3])
#define TOA(w) { \
    char *c = (char *)&w; \
    if (isprint(c[0]) && isprint(c[1]) && isprint(c[2]) && isprint(c[3])) \
        printf("%c%c%c%c\n", c[3], c[2], c[1], c[0]); \
}
#define TOX(s, bufsize, buf) \
{ \
    int i; \
    int slen = strlen(s); \
    for (i = 0; (i < slen) && (i < (bufsize << 1)); i++) { \
        s[i] |= 0x20; \
        if (s[i] >= '0' && (s[i] <= '9')) \
            s[i] -= '0'; \
        else \
            s[i] -= 87; \
        if (i % 2) \
            buf[i >> 1] |= s[i]; \
        else \
            buf[i >> 1] = s[i] << 4; \
    } \
}

//---[ prototypes: ]------------------------------------------------------------
void lzss_compress(unsigned char *in, unsigned int len, FILE *outfile);
void lzss_uncompress(unsigned char *in, unsigned int len, FILE *outfile);
int aes_decrypt(void *in, size_t len, unsigned char **out, unsigned char *iv, unsigned char *key);
int aes_encrypt(void *in, size_t len, unsigned char **out, unsigned char *iv, unsigned char *key);
void print_hex(void *data, size_t len, unsigned int flag);

//---[ structs: ]---------------------------------------------------------------
struct img3 {
    unsigned int magic;
    unsigned int filesize;
    unsigned int contentsize;
    unsigned int certarea;
    unsigned int filetype;
};

struct tag {
    unsigned int magic;
    unsigned int blocksize;
    unsigned int payloadsize;
};

//---[ flags: ]----------------------------------------------------------------
// hex output flags:
#define HEX_SKIP_ASCII  1
#define HEX_SKIP_WS     2
#define HEX_SKIP_TAB    4
#define HEX_SKIP_NL     8



#endif
