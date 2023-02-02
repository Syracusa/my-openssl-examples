#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#define TESTDATALEN 1024
#define KEYLEN 16

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

typedef enum
{
    VERIFY_OK,
    VERIFY_FAIL
} HmacVerifyRes;

void gen_rand(void *rand_buf, size_t len)
{
    BIGNUM *bn = BN_new();
    int res = BN_rand(bn, 8 * (len),
                      BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    if (res == 1){
        printf("BN_rand success\n");
    } else {
        printf("BN_rand failed\n");
    }
    printf("\n");

    BN_bn2bin(bn, rand_buf);
    BN_free(bn);
}

void calc_hmac(
    void *key, size_t keylen,
    void *data, size_t datalen,
    void *out_sign_buf, size_t *inout_sign_len)
{
    HMAC(EVP_sha256(), key, keylen,
         data, datalen, out_sign_buf, (unsigned int *)inout_sign_len);
}

HmacVerifyRes verify_hmac(
    void *key, size_t keylen,
    void *data, size_t datalen,
    void *sign, size_t signlen)
{
    unsigned char csign[100];
    uint32_t csign_len = 100;
    HMAC(EVP_sha256(), key, keylen,
         data, datalen, csign, &csign_len);

    if (csign_len != signlen)
    {
        return VERIFY_FAIL;
    }

    int cmpres = memcmp(csign, sign, signlen);
    if (cmpres == 0)
    {
        return VERIFY_OK;
    }
    else
    {
        return VERIFY_FAIL;
    }
}

int main()
{
#if 0 /* Seeding */
    { 
#if 0
        int res = RAND_poll();
        if (res == 1){
            printf("RAND_poll success\n");
        } else {
            printf("RAND_poll fail\n");
        }
#else
        struct timespec currtime;
        clock_gettime(0 /* CLOCK_REALTIME*/, &currtime);
        RAND_seed(&currtime, sizeof(currtime));
#endif

        if (RAND_status() == 1){
            printf("Seeding success\n");
        } else {
            printf("Seeding fail\n");
        }
    }
#endif
    unsigned char key[KEYLEN];
    memset(key, 0x00, KEYLEN);
    gen_rand(key, KEYLEN);

    printf("[Generated key]\n");
    hex_dump(key, KEYLEN, stdout);
    printf("\n");

    unsigned char testdata[TESTDATALEN];
    memset(testdata, 0x00, TESTDATALEN);

    sprintf((char *)testdata, "This is test data\n");

    unsigned char hmacbuf[100];
    size_t hmacsize = 100;

    { /* Calc HMAC */
        calc_hmac(key, KEYLEN, testdata, TESTDATALEN, hmacbuf, &hmacsize);
        printf("[Calculated HMAC]\n");
        hex_dump(hmacbuf, hmacsize, stdout);
        printf("\n");
    }

    printf("[Verify test]\n");
    { /* Verify HMAC */
        HmacVerifyRes res = verify_hmac(key, KEYLEN, testdata, TESTDATALEN, hmacbuf, hmacsize);

        if (res == VERIFY_OK)
        {
            printf("HMAC verify success(Original data)\n");
        }
        else
        {
            printf("HMAC verify fail(Original data)\n");
        }
    }

    {                                   /* Verify HMAC(with falsified data) */
        testdata[TESTDATALEN - 1] -= 1; /* falsify data */

        HmacVerifyRes res = verify_hmac(key, KEYLEN, testdata, TESTDATALEN, hmacbuf, hmacsize);

        if (res == VERIFY_OK)
        {
            printf("HMAC verify success(Falsified data)\n");
        }
        else
        {
            printf("HMAC verify fail(Falsified data)\n");
        }
    }
    return 0;
}