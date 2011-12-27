#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>

#include "kcache.h"

// the last 4 bytes are not encrypted with decodeimg3.pl
// define 'SKIP_LAST_WORD' to make this output identical
#define SKIP_LAST_WORD

int aes_decrypt(void *in, size_t len, unsigned char **out, unsigned char *iv, unsigned char *key)
{
    AES_KEY aeskey;
    int ret;

    if (!len)
        return 0;

    ret = AES_set_decrypt_key(key, 256, &aeskey);
    assert(!ret);

    printf("(len: %zd pad: %zd)\n", len, len % 16);
    len += len % 16;

    *out = calloc(1, len); // consider padding..
    assert(*out);

#ifdef SKIP_LAST_WORD
    AES_cbc_encrypt(in, *out, len-4, &aeskey, iv, AES_DECRYPT); 
    memcpy(*out + (len - 4), in + (len - 4), 4);
#else
    AES_cbc_encrypt(in, *out, len, &aeskey, iv, AES_DECRYPT); 
#endif

    printf("\nplaintext (excerpt):\n");
    print_hex(in, 128, 0);

    printf("decrypted (excerpt):\n");
    print_hex(*out, 128, 0);

    return 0;
}

int aes_encrypt(void *in, size_t len, unsigned char **out, unsigned char *iv, unsigned char *key)
{
    AES_KEY aeskey;
    int ret;

    if (!len)
        return 0;

    ret = AES_set_encrypt_key(key, 256, &aeskey);
    assert(!ret);

    printf("(len: %ld pad: %ld)\n", len, len % 16);
    len += len % 16;

    *out = calloc(1, len); // consider padding..
    assert(*out);

#ifdef SKIP_LAST_WORD
    AES_cbc_encrypt(in, *out, len-4, &aeskey, iv, AES_ENCRYPT); 
    memcpy(*out + (len - 4), in + (len - 4), 4);
#else
    AES_cbc_encrypt(in, *out, len, &aeskey, iv, AES_ENCRYPT); 
#endif

    printf("\nplaintext (excerpt):\n");
    print_hex(in, 128, 0);

    printf("ciphertext (excerpt):\n");
    print_hex(*out, 128, 0);

    return 0;
}


