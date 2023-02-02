#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static void hex_dump(void *addr, int len, FILE *stream)
{
    fprintf(stream, "length of hexdump = %d\n", len);
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    for (i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
                fprintf(stream, " %s\n", buff);

            fprintf(stream, " %04x ", i);
        }

        fprintf(stream, " %02x", pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0)
    {
        fprintf(stream, " ");
        i++;
    }

    fprintf(stream, " %s\n", buff);
}

static uint32_t do_hash(void *data, uint32_t datalen,
                        void *out_hash_buf, uint32_t *inout_hash_len)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, datalen);
    SHA256_Final(out_hash_buf, &sha256);
    OPENSSL_cleanse(&sha256, sizeof(sha256));

    *inout_hash_len = 32;

    return 0;
}

static void get_key_ptr(EC_KEY *k,
                        unsigned char **prikeyp, uint32_t *prikeylen,
                        unsigned char **pubkeyp, uint32_t *pubkeylen)
{
    static unsigned char prikeybuf[1000];
    static unsigned char pubkeybuf[1000];

    const EC_GROUP *group = EC_KEY_get0_group(k);
    if (!group)
    {
        fprintf(stderr, "error: EC_KEY_get0_group() failed.\n");
        return;
    }

    size_t octets_len = 256;

    const EC_POINT *pp = EC_KEY_get0_public_key(k);
    octets_len = EC_POINT_point2oct(group, pp,
                                    POINT_CONVERSION_UNCOMPRESSED,
                                    pubkeybuf, octets_len, NULL);

    *pubkeylen = octets_len;

    octets_len = 256;
    const BIGNUM *bn = EC_KEY_get0_private_key(k);
    octets_len = BN_bn2mpi(bn, prikeybuf);

    *prikeylen = octets_len;

    *pubkeyp = pubkeybuf;
    *prikeyp = prikeybuf;
}

static uint32_t set_eckey(EC_KEY **key)
{
    *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
    {
        fprintf(stderr, "Can't create key\n");
        ERR_print_errors_fp(stderr);
    }
    int res = EC_KEY_generate_key(*key);
    if (res == 0)
    {
        fprintf(stderr, "Key generation fail\n");
        ERR_print_errors_fp(stderr);
    }
    res = EC_KEY_check_key(*key);
    if (res == 0)
    {
        fprintf(stderr, "Key check fail\n");
        ERR_print_errors_fp(stderr);
    }

    unsigned char *prikey;
    unsigned char *pubkey;
    uint32_t prikeylen;
    uint32_t pubkeylen;

    get_key_ptr(*key, &prikey, &prikeylen, &pubkey, &pubkeylen);
    printf("=== GENERATED PRIVATE KEY ===\n");
    hex_dump(prikey, prikeylen, stdout);
    printf("=== GENERATED PUBLIC KEY ===\n");
    hex_dump(pubkey, pubkeylen, stdout);

    return 0;
}

static uint32_t ecdsa_sign(EC_KEY *key,
                           void *data, uint32_t datalen,
                           void *out_sign_buf, uint32_t *inout_sign_len)
{
    if (key == NULL)
        set_eckey(&key);

    uint32_t hashlen = 32;
    unsigned char hashbuf[hashlen];

    do_hash(data, datalen, hashbuf, &hashlen);

    if (!ECDSA_sign(0, hashbuf, hashlen, out_sign_buf, inout_sign_len, key))
    {
        /* error */
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

static uint32_t ecdsa_verify(EC_KEY *key,
                             void *data, uint32_t datalen,
                             void *sign, uint32_t signlen)
{
    if (key == NULL)
        return -1;

#if 1
    uint32_t hashlen = 32;
    unsigned char hashbuf[hashlen];
    do_hash(data, datalen, hashbuf, &hashlen);
#endif

    int ret = ECDSA_verify(0, hashbuf, hashlen, sign, signlen, key);
    switch (ret)
    {
    case -1:
    {
        /* error */
        ERR_print_errors_fp(stderr);
        return -1;
        break;
    }
    case 0:
        return -1;
        break;
    case 1:
        return 1;
        break;
    default:
        return -1;
        break;
    }
}

int main()
{
    EC_KEY *key;
    set_eckey(&key);

    int datalen = 100;
    unsigned char data[datalen];
    memset(data, 0x00, datalen);
    sprintf(data, "This is test data\n");

    unsigned char signbuf[100];
    uint32_t signlen = 100;

    ecdsa_sign(key, data, datalen, signbuf, &signlen);
    int vres = ecdsa_verify(key, data, datalen, signbuf, signlen);

    if (vres == 1)
    {
        printf("Verify Success\n");
    }
    else
    {
        printf("Verify failed\n");
    }

    return 0;
}