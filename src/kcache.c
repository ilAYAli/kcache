// by petter wahlman, petter@wahlman.no
//
// for compatibility with decodeimg3.pl, compile with -D SKIP_LAST_WORD
// and supply --nostrip --nodecompress

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kcache.h"

// the last 4 bytes are not encrypted with decodeimg3.pl
// define 'SKIP_LAST_WORD' to make this output identical
//#define SKIP_LAST_WORD

#define FILE_RELEASE    "kernelcache.release"
#define FILE_HDR        "kernelcache.hdr"
#define FILE_LZSS       "kernelcache.lzss"
#define FILE_BIN        "kernelcache.bin"

//---[ cml switches: ]----------------------------------------------------------
int opt_encrypt = 0;
int opt_decrypt = 1;
int opt_compress = 0;
int opt_decomp = 1;
int opt_strip = 1;


void print_usage(void)
{
    printf("usage: img3 [option(s)]\n"
           "    -h,  --help                 this information\n"
           "    -i,  --in <filename>        input file (default ./kcache/kernelcache.release.n90,\n"
           "                                or ./kcache/kernelcache.bin if --encrypt is supplied)\n"
           "    -w,  --wd <directory>       work directory (default ./kcache)\n"
           "    -k,  --key <key>            AES key\n"
           "    -v,  --iv  <iv>             AES init vector\n"
           "    -e,  --encrypt              encrypt data (inverse of default)\n"
           // don't use these flags unless you know what you are doing:
           //"    -e,  --encrypt              encrypt data\n"
           //"    -c,  --compress             compress data\n"
           //"    -D,  --nodecompess          don't decompress lzss container\n"
           //"    -S,  --nostrip              don't strip lzss header\n"
           );
}

struct tag *find_tag(unsigned char *data, unsigned int len, char *tagname)
{
    unsigned char *ptr;
    struct tag *tag;

    ptr = data;
    do {
        tag = (typeof(tag)) ptr;
        if (!tagname) {
            printf("0x%08lx 0x%08x: ", ptr - data, tag->payloadsize);
            TOA(tag->magic);
        } else {
            if (tag->magic == TOI(tagname))
                return tag;
            else if (tag->magic == TOI("DATA"));// type of image:
            else if (tag->magic == TOI("TYPE"));// type of image:
            else if (tag->magic == TOI("SDOM"));// security domain:
            else if (tag->magic == TOI("PROD"));// production mode:
            else if (tag->magic == TOI("CHIP"));// chip to be used:
            else if (tag->magic == TOI("BORD"));// board to be used:
            else if (tag->magic == TOI("KBAG"));// key and iv required to decrypt encrypted data
            else if (tag->magic == TOI("SHSH"));// encrypted sha1 hash of the file:
            else if (tag->magic == TOI("CERT"));// certificate:
            else if (tag->magic == TOI("ECID"));// exclusive chip id:
            else if (tag->magic == TOI("SEPO"));// security epoch
            else if (tag->magic == TOI("VERS"));// iBoot version of the image
            else {
                fprintf(stderr, "error, unknown magic\n"); 
                break;
            }
        }
        ptr += tag->blocksize;
    } while(((char *)ptr - (char *)data) < len);

    return NULL;
}

// todo: consider creating dest. directories
int copy_file(char *src, char *dst, mode_t mode)
{
    char buf[4096];
    int fd[2];
    int nr, nw;

    fd[0] = open(src, O_RDONLY);
    if (-1 == fd[0]) {
        fprintf(stderr, "error, could not open: %s: %s\n", src, strerror(errno));
        return 1;
    }

    fd[1] = open(src, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (-1 == fd[0]) {
        fprintf(stderr, "error, could not open: %s: %s\n", dst, strerror(errno));
        return 1;
    }

    for (;;) {
        nw = read(fd[0], buf, sizeof(buf));
        if (nw < 1) break;
        nr = write(fd[1], buf, nw);
        if (nw < 1) break;
    }

    close(fd[0]);
    close(fd[1]);

    return 0;
}

// encrypt and compress
int kcache_encrypt(char *in, char *wd, unsigned char *iv, unsigned char *key)
{
    unsigned char *ciphertext;
    unsigned char *data;
    struct stat st;
    struct img3 *img;
    struct tag *tag;
    FILE *fp;
    int fd;

    // compress data, and copy the result to output file
    printf("opening:     %s\n", in);
    fd = open(in, O_RDONLY);
    if (-1 == fd) {
        fprintf(stderr, "error, unable to open %s: %s\n", in, strerror(errno));
        return 1;
    }

    if (chdir(wd)) {
        fprintf(stderr, "error, could not chdir to %s: %s\n", wd, strerror(errno));
        return 1;
    }

    fstat(fd, &st);
    data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == data) {
        perror("mmap");
        close(fd);
        return 1;
    }
    close(fd);

    printf("compressing: %s/mod.kernelcache.lzss\n", wd);
    fp = fopen("./mod.kernelcache.lzss", "wb");
    assert(fp);

    lzss_compress(data, st.st_size, fp);
    fclose(fp);
    munmap(data, st.st_size);

//-------------------------------------------------------------------------------------------------
    unsigned char *buf;
    size_t size;

    printf("opening:     %s/kernelcache.hdr", wd);
    fd = open("./kernelcache.hdr", O_RDONLY);
    if (-1 == fd) {
        fprintf(stderr, "error, unable to open %s: %s\n", "kernelcache.hdr", strerror(errno));
        return 1;
    }

    fstat(fd, &st);
    size = st.st_size;

    buf = malloc(size);
    read(fd, buf, size);
    close(fd);

    printf("hdr:\n");
    print_hex(buf, 64, 0);

    printf("opening:     %s/mod.kernelcache.lzss\n", wd);
    fd = open("./mod.kernelcache.lzss", O_RDONLY);
    if (-1 == fd) {
        fprintf(stderr, "error, unable to open %s: %s\n", "mod.kernelcache.lzss", strerror(errno));
        return 1;
    }

    fstat(fd, &st);
    buf = realloc(buf, st.st_size + size);

    read(fd, buf + size, st.st_size);
    close(fd);

    printf("creating:    %s/mod.kernelcache.data.pt\n", wd);
    fd = open("./mod.kernelcache.data.pt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (-1 == fd) {
        fprintf(stderr, "error, unable to open %s: %s\n", "mod.kernelcache.data.pt", strerror(errno));
        return 1;
    }

    write(fd, buf, size + st.st_size);
    close(fd);

    tag = NULL;

    printf("creating:    %s/mod.kernelcache.data\n", wd);
    printf("\nAES encrypt:");
    aes_encrypt(buf, size + st.st_size, &ciphertext, iv, key);
    free(buf); buf = NULL;

    printf("locating data tag:\n");
    printf("opening:     %s/kernelcache.release.n90\n", wd);
    fd = open("./kernelcache.release.n90", O_RDONLY);
    if (-1 == fd) {
        fprintf(stderr, "error, unable to open %s: %s\n", in, strerror(errno));
        return 1;
    }

    fstat(fd, &st);
    buf = malloc(st.st_size);
    read(fd, buf, st.st_size);

    // error:?
    close(fd);
    img = (typeof(img)) buf;

    tag = find_tag(buf + sizeof(*img), img->contentsize, "DATA");
    if (!tag) {
        fprintf(stderr, "error, unable to locate \"DATA\" tag\n");
        return 1;
    }

    printf("tag found at: 0x%08lx\n", (char *)tag - (char *)buf);
    printf("creating:    %s/mod.kernelcache.data\n", wd);
    fd = open("./mod.kernelcache.data", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (-1 == fd) {
        fprintf(stderr, "error, unable to open %s: %s\n", "mod.kernelcache.data", strerror(errno));
        return 1;
    }

    write(fd, ciphertext, tag->payloadsize);
    free(buf); buf = NULL;
    free(ciphertext); ciphertext = NULL;

    // copy kernelcache.release.n90 -> mod.kernelcache.release.n90
    // inject data in tag offset

    return 0;
}

// decrypt and uncompress
// TODO: add contentsize, not img?
int kcache_decrypt(char *in, char *wd, unsigned char *iv, unsigned char *key)
{
    unsigned char *plaintext;
    unsigned char *data;
    unsigned char *ptr;
    struct stat st;
    struct img3 *img;
    struct tag *tag;
    FILE *fp;
    int fd;

    // open input file:
    printf("opening:     %s\n", in);
    fd = open(in, O_RDONLY);
    if (-1 == fd) {
        perror(in);
        return 1;
    }

    if (chdir(wd)) {
        fprintf(stderr, "error, could not chdir to %s: %s\n", wd, strerror(errno));
        return 1;
    }

    fstat(fd, &st);
    data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    // check input file integrity:
    img = (typeof(img)) data;
    if (img->magic != TOI("Img3")) {
        fprintf(stderr, "error, incorrect magic.\n");
        goto end;
    }

    if (img->filesize != st.st_size) {
        fprintf(stderr, "error, incorrect filesize\n");
        goto end;
    }

    printf("magic:       ");    TOA(img->magic);
    printf("filesize:    %d\n", img->filesize);
    printf("contentsize: %d\n", img->contentsize);
    printf("certarea:    %d\n", img->certarea);
    printf("filetype:    ");    TOA(img->filetype);
    printf("\n");

    img = (typeof(img)) data;
    ptr = data + sizeof(*img);

    // print all tags:
    find_tag(ptr, img->contentsize, NULL);

    tag = find_tag(data + sizeof(*img), img->contentsize, "DATA");
    if (!tag) {
        fprintf(stderr, "error, unable to locate \"DATA\" tag\n");
        return 1;
    }

//  write tag:
    printf("creating:    %s/kernelcache.data\n", wd);
    fd = open("./kernelcache.data", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, tag + 1, tag->payloadsize);
    close(fd);

// write decrypted tag
    printf("\nAES decrypt:");
    aes_decrypt(tag + 1, tag->payloadsize, &plaintext, iv, key);
    printf("creating:    %s/kernelcache.data.pt\n", wd);
    fd = open("./kernelcache.data.pt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, plaintext, tag->payloadsize);
    close(fd);

// write decrypted header:
    printf("creating:    %s/kernelcache.hdr\n", wd);
    fd = open("./kernelcache.hdr", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, plaintext, 0x180);
    close(fd);

// write decrypted lzss container:
    printf("creating:    %s/kernelcache.lzss\n", wd);
    fd = open("./kernelcache.lzss", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, plaintext + 0x180, tag->payloadsize - 0x180);
    close(fd);

// write extracted MACH-O kernelcache
    printf("creating:    %s/kernelcache.bin\n", wd);
    fp = fopen("./kernelcache.bin", "wb");
    assert(fp);
    lzss_uncompress(plaintext + 0x180, tag->payloadsize - 0x180, fp);
    fclose(fp);

end:
    free(plaintext); plaintext = NULL;
    if (data)
        munmap(data, st.st_size);

    return 0;
}

int main(int argc, char **argv)
{
    char *in;
    char *wd;
    unsigned char iv[] = {  
        0x30, 0x1c, 0x0d, 0xb0, 0xf6, 0xfc, 0x3a, 0x92,
        0xc3, 0x4f, 0x34, 0xb2, 0xdf, 0xf5, 0xd9, 0x2f};
    unsigned char key[] = { // IOS 4.3.3, Durango 8J2:
        0x65, 0xc3, 0x51, 0x33, 0x0f, 0x82, 0x48, 0x89,
        0xfe, 0x25, 0xb1, 0x4e, 0x2d, 0x0c, 0xb5, 0xe2,
        0x91, 0x99, 0x1a, 0x74, 0x9f, 0x13, 0x76, 0x1b,
        0x82, 0x5a, 0x70, 0xf3, 0x17, 0xf0, 0x05, 0xaa};

    in = wd = NULL;
    while (1) {
        unsigned int c;
        int option_index = 0;
        static struct option long_options[] = {
            { "help",     0, 0, 'h' },
            { "in",       1, 0, 'i' }, 
            { "wd",       1, 0, 'w' },
            { "key",      1, 0, 'k' },
            { "iv",       1, 0, 'v' },
            { "encrypt",  0, 0, 'e' }, 
            // developer opts:
            { "compress", 0, 0, 'c' },
            { "nodecomp", 0, 0, 'D' },
            { "nostrip",  0, 0, 'S' },
            { NULL,       0, 0,  0  }
        };

        c = getopt_long(argc, argv, "hi:w:k:v:ecDS", long_options, &option_index);
        if (-1 == c)
            break;

        switch (c) {
            case 'h':
                print_usage();
                exit(0);
            case 'i':
                in = strdup(optarg);
                break;
            case 'w':
                wd = optarg;
                break;
            case 'k':
                TOX(optarg, sizeof(key), key);
                break;
            case 'v':
                TOX(optarg, sizeof(iv), iv);
                break;
            case 'e':
                opt_encrypt = 1;
                break;
             case 'D': // nodecomp
                opt_decomp = 0;
                break;
            case 'S': // nostrip
                opt_strip = 0;
                break;
            case 'c':
                opt_compress = 1;
                break;
            default:
                exit(1);
        }
    }

    if (!in) {
        fprintf(stderr, "error, no input file specified\n");
        return 1;
    }

    if (opt_decomp && opt_compress) {
        fprintf(stderr, "error, --decompress and --compress are mutually exclusive\n");
        return 1;
    }

    printf("iv:          ");
    print_hex(iv, sizeof(iv), -1);

    printf("key:         ");
    print_hex(key, sizeof(key), -1);

    if (opt_encrypt) {
        char *tmp = strdup(in);
        //in = "./kcache/kernelcache.bin";
        //wd = "./kcache";
        asprintf(&wd, "%s", dirname(tmp));
        free(tmp);

        printf("in:          %s\n", in);
        printf("wd:          %s\n", wd);
        printf("\n");
        kcache_encrypt(in, wd, iv, key);
    } else {
        char *tmp = strdup(in);
        //in = "./kcache/kernelcache.release.n90";
        //wd = "./kcache";
        asprintf(&wd, "%s/kcache", dirname(tmp));
        free(tmp);
        mkdir(wd, 0755);

        printf("in:          %s\n", in);
        printf("wd:          %s\n", wd);
        printf("\n");
        kcache_decrypt(in, wd, iv, key);
    }

    return 0;
}
