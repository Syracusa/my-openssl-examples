
#include <assert.h>
#include <stdio.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

static uint8_t PrivateKey1[] =
    {
        0x51, 0x9B, 0x42, 0x3D, 0x71, 0x5F, 0x8B, 0x58, 0x1F, 0x4F, 0xA8, 0xEE, 0x59, 0xF4, 0x77, 0x1A,
        0x5B, 0x44, 0xC8, 0x13, 0x0B, 0x4E, 0x3E, 0xAC, 0xCA, 0x54, 0xA5, 0x6D, 0xDA, 0x72, 0xB4, 0x64};

static uint8_t PublicKey1X[] =
    {
        0x1C, 0xCB, 0xE9, 0x1C, 0x07, 0x5F, 0xC7, 0xF4, 0xF0, 0x33, 0xBF, 0xA2, 0x48, 0xDB, 0x8F, 0xCC,
        0xD3, 0x56, 0x5D, 0xE9, 0x4B, 0xBF, 0xB1, 0x2F, 0x3C, 0x59, 0xFF, 0x46, 0xC2, 0x71, 0xBF, 0x83};

static uint8_t PublicKey1Y[] =
    {
        0xCE, 0x40, 0x14, 0xC6, 0x88, 0x11, 0xF9, 0xA2, 0x1A, 0x1F, 0xDB, 0x2C, 0x0E, 0x61, 0x13, 0xE0,
        0x6D, 0xB7, 0xCA, 0x93, 0xB7, 0x40, 0x4E, 0x78, 0xDC, 0x7C, 0xCD, 0x5C, 0xA8, 0x9A, 0x4C, 0xA9};

static uint8_t PrivateKey2[] =
    {
        0x2d, 0x9b, 0xe7, 0x2b, 0x4f, 0xe4, 0x5d, 0x71, 0xa9, 0xdd, 0xa6, 0xf7, 0xd1, 0xbd, 0xe5, 0x50,
        0xfe, 0x37, 0xeb, 0xb7, 0x3d, 0xcf, 0x77, 0x3c, 0x75, 0x32, 0x4c, 0x8a, 0xc6, 0x61, 0x5a, 0x71};

static uint8_t PublicKey2X[] =
    {
        0x76, 0xa9, 0x8e, 0x9e, 0x3d, 0xab, 0x60, 0x5f, 0x5a, 0xf0, 0xe9, 0x7f, 0x23, 0x74, 0xf9, 0x99,
        0x8a, 0xfc, 0xb3, 0x43, 0x34, 0x59, 0x1f, 0x91, 0xa5, 0x01, 0x67, 0x3e, 0x6e, 0xed, 0xa7, 0x39};

static uint8_t PublicKey2Y[] =
    {
        0x05, 0xd0, 0x6b, 0xcd, 0xf8, 0xca, 0x53, 0xc1, 0x09, 0xbc, 0xf5, 0x1b, 0x7a, 0x27, 0xe6, 0x6f,
        0xab, 0xdf, 0x28, 0x31, 0x4d, 0x9c, 0x2e, 0xd7, 0x80, 0x67, 0xa9, 0x33, 0xc3, 0x0c, 0x42, 0xec};

#define HEXDUMP_COL 16
static void hexdump(const void *data, const int len, FILE *stream)
{
    char ascii_buf[HEXDUMP_COL + 1];
    const unsigned char *ptr = data;

    ascii_buf[HEXDUMP_COL] = '\0';

    int linecount = 0;
    int lineoffset;
    for (int i = 0; i < len; i++)
    {
        lineoffset = i % HEXDUMP_COL;

        /* Print offset if newline */
        if (lineoffset == 0)
            fprintf(stream, " %04x ", (unsigned int)i);

        /* Add space at every 4 bytes.. */
        if (lineoffset % 4 == 0)
            fprintf(stream, " ");

        fprintf(stream, " %02x", ptr[i]);
        if ((ptr[i] < 0x20) || (ptr[i] > 0x7e))
            ascii_buf[lineoffset] = '.';
        else
            ascii_buf[lineoffset] = ptr[i];

        /* Print ASCII if end of line */
        if (lineoffset == HEXDUMP_COL - 1)
        {
            fprintf(stream, "    %s\n", ascii_buf);
            linecount++;

            /* Print additional newline at every 5 lines */
            if (linecount != 0 && linecount % 5 == 0)
                fprintf(stream, "\n");
        }
    }

    for (int i = lineoffset + 1; i < HEXDUMP_COL; i++)
    {
        lineoffset = i % HEXDUMP_COL;
        if (lineoffset % 4 == 0)
            fprintf(stream, " ");
        fprintf(stream, " ..");
    }

    ascii_buf[lineoffset + 1] = '\0';
    fprintf(stream, "    %s\n", ascii_buf);
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

    fprintf(stderr, "test key1\n");
    *pubkeylen = octets_len;

    octets_len = 256;
    const BIGNUM *bn = EC_KEY_get0_private_key(k);
    octets_len = BN_bn2bin(bn, prikeybuf);

    *prikeylen = octets_len;

    *pubkeyp = pubkeybuf;
    *prikeyp = prikeybuf;
}

void set_test_key(EC_KEY **alice, EC_KEY **bob)
{
    *alice = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    *bob = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    BIGNUM *bn_pubkey1x = BN_bin2bn(PublicKey1X, sizeof(PublicKey1X), NULL);
    BIGNUM *bn_pubkey1y = BN_bin2bn(PublicKey1Y, sizeof(PublicKey1Y), NULL);
    BIGNUM *bn_pubkey2x = BN_bin2bn(PublicKey2X, sizeof(PublicKey2X), NULL);
    BIGNUM *bn_pubkey2y = BN_bin2bn(PublicKey2Y, sizeof(PublicKey2Y), NULL);

    if (!bn_pubkey1x || !bn_pubkey1y || !bn_pubkey2x || !bn_pubkey2y){
        fprintf(stderr, "BIGNUM is null\n");
        exit(2);
    }

    int res;
    res = EC_KEY_set_public_key_affine_coordinates(*alice, bn_pubkey1x, bn_pubkey1y);
    if (res != 1)
        fprintf(stderr, "EC_KEY_set_public_key_affine_coordinates failed! %d\n", res);
    res = EC_KEY_set_public_key_affine_coordinates(*bob, bn_pubkey2x, bn_pubkey2y);
    if (res != 1)
        fprintf(stderr, "EC_KEY_set_public_key_affine_coordinates failed! %d\n", res);

    res = EC_KEY_oct2priv(*alice, PrivateKey1, sizeof(PrivateKey1));
    if (res != 1)
        fprintf(stderr, "EC_KEY_set_public_key_affine_coordinates failed!\n");
    res = EC_KEY_oct2priv(*bob, PrivateKey2, sizeof(PrivateKey2));
    if (res != 1)
        fprintf(stderr, "EC_KEY_set_public_key_affine_coordinates failed!\n");

    uint32_t prikeylen;
    uint32_t pubkeylen;
    unsigned char *prikeyptr;
    unsigned char *pubkeyptr;

    get_key_ptr(*alice, &prikeyptr, &prikeylen, &pubkeyptr, &pubkeylen);

    hexdump(prikeyptr, prikeylen, stdout);
    hexdump(pubkeyptr, pubkeylen, stdout);

    get_key_ptr(*bob, &prikeyptr, &prikeylen, &pubkeyptr, &pubkeylen);

    hexdump(prikeyptr, prikeylen, stdout);
    hexdump(pubkeyptr, pubkeylen, stdout);
}

EC_KEY *set_generated_key(void)
{
    EC_KEY *key;
    if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
    {
        printf("Failed to create key curve\n");
        return NULL;
    }

    if (1 != EC_KEY_generate_key(key))
    {
        printf("Failed to generate key\n");
        return NULL;
    }

    uint32_t prikeylen;
    uint32_t pubkeylen;
    unsigned char *prikeyptr;
    unsigned char *pubkeyptr;

    get_key_ptr(key, &prikeyptr, &prikeylen, &pubkeyptr, &pubkeylen);

    hexdump(prikeyptr, prikeylen, stdout);
    hexdump(pubkeyptr, pubkeylen, stdout);

    return key;
}

unsigned char *get_secret(EC_KEY *key, const EC_POINT *peer_pub_key,
                          size_t *secret_len)
{
    int field_size;
    unsigned char *secret;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    *secret_len = (field_size + 7) / 8;

    if (NULL == (secret = OPENSSL_malloc(*secret_len)))
    {
        printf("Failed to allocate memory for secret");
        return NULL;
    }

    *secret_len = ECDH_compute_key(secret, *secret_len,
                                   peer_pub_key, key, NULL);

    if (*secret_len <= 0)
    {
        OPENSSL_free(secret);
        return NULL;
    }
    return secret;
}

int main(int argc, char *argv[])
{
    EC_KEY *alice;
    EC_KEY *bob;

#if 0
    alice = set_generated_key();
    bob = set_generated_key();
#else
    fprintf(stderr, "Set test key\n");
    set_test_key(&alice, &bob);
    fprintf(stderr, "Testkey set done\n");
#endif

    assert(alice != NULL && bob != NULL);

    const EC_POINT *alice_public = EC_KEY_get0_public_key(alice);
    const EC_POINT *bob_public = EC_KEY_get0_public_key(bob);

    size_t alice_secret_len;
    size_t bob_secret_len;

    unsigned char *alice_secret = get_secret(alice, bob_public, &alice_secret_len);
    unsigned char *bob_secret = get_secret(bob, alice_public, &bob_secret_len);
    assert(alice_secret != NULL && bob_secret != NULL && alice_secret_len == bob_secret_len);

    for (int i = 0; i < alice_secret_len; i++)
        assert(alice_secret[i] == bob_secret[i]);

    hexdump(alice_secret, alice_secret_len, stdout);
    hexdump(bob_secret, bob_secret_len, stdout);

    EC_KEY_free(alice);
    EC_KEY_free(bob);
    OPENSSL_free(alice_secret);
    OPENSSL_free(bob_secret);

    return 0;
}