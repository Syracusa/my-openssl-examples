#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define IV_LEN 16
#define SESSION_KEY_LEN 16

EVP_CIPHER_CTX *cipher_ctx;

unsigned char sessionkey[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6'};
unsigned char ciphertext[] = {
    0xc5, 0xbd, 0x6d, 0x4e, 0xd6, 0x63, 0xff, 0xed, 0x39, 0xfd, 0x72, 0x25, 0x5a, 0x6a, 0x1f, 0x22,
    0x6a, 0x93, 0xb2, 0xef, 0x56, 0xfe, 0x99, 0xc7, 0xa1, 0x09, 0x8e, 0xe0, 0xab, 0x22, 0x85, 0xe1,
    0x18, 0x5b, 0x9c, 0x2b, 0x0c, 0x2a, 0xe2, 0x67, 0x91, 0x08, 0x0e, 0x1d, 0x33, 0x0f, 0x34, 0xb9,
    0x6c, 0xe3, 0xcd, 0xb2, 0x58, 0x73, 0x5f, 0x4a, 0xfd, 0x04, 0xce, 0xe6, 0x09, 0x22, 0x33, 0xfe,
    0x09, 0x28};

unsigned char plaintext[100];

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

    for (int i = lineoffset + 1; i < HEXDUMP_COL; i++){
        lineoffset = i % HEXDUMP_COL;
        if (lineoffset % 4 == 0)
            fprintf(stream, " ");
        fprintf(stream, " ..");
    }

    ascii_buf[lineoffset + 1] = '\0';
    fprintf(stream, "    %s\n", ascii_buf);
}

static uint32_t init_sym_crypt(int do_encrypt, void *iv)
{
    if (cipher_ctx == NULL)
    {
        cipher_ctx = EVP_CIPHER_CTX_new();
        // EVP_CIPHER_CTX_set_padding( cipher_ctx, SESSION_KEY_LEN);
    }

    const EVP_CIPHER *evp_cipher = EVP_aria_128_cfb8();
    if (evp_cipher == NULL)
    {
        return -1;
    }

    EVP_CipherInit_ex(cipher_ctx,
                      EVP_aria_128_cfb8(),
                      NULL,
                      sessionkey,
                      iv,
                      do_encrypt);

    if (EVP_CIPHER_CTX_key_length(cipher_ctx) != SESSION_KEY_LEN)
    {
        fprintf(stderr,
                "Key Length Error! expected : %d get : %d\n",
                SESSION_KEY_LEN,
                EVP_CIPHER_CTX_key_length(cipher_ctx));
        exit(2);
    }

    return 1;
}

uint32_t sym_decrypt(void *cipher_text,        
                            uint32_t cipher_text_len, 
                            void *out_plain_text_buf,
                            uint32_t *out_plain_text_len)
{
    *out_plain_text_len = 0;

    fprintf(stderr, "== Cipher text(Before Decrypt) ==\n");
    int cdlen = cipher_text_len;
    hexdump(cipher_text, cdlen, stderr);

    int ires = init_sym_crypt(0 /* Decrypt */, cipher_text);
    if (ires < 0)
    {
        return ires;
    }

    int outlen = *out_plain_text_len;

    if (!EVP_CipherUpdate(cipher_ctx,
                          out_plain_text_buf, &outlen,
                          (uint8_t *)cipher_text + IV_LEN,
                          cipher_text_len - IV_LEN))
    {
        /* Error */
        ERR_print_errors_fp(stderr);
        return -2;
    }

    int finallen;

    if (!EVP_CipherFinal_ex(cipher_ctx,
                            (uint8_t *)out_plain_text_buf + outlen, &finallen))
    {
        /* Error */
        ERR_print_errors_fp(stderr);
        return -3;
    }

    *out_plain_text_len = outlen + finallen;

    fprintf(stderr, "== Plain text(After Decrypt) ==\n");
    int pdlen = *out_plain_text_len;
    hexdump(out_plain_text_buf, pdlen, stderr);

    return 1;
}

int main()
{
    uint32_t out_plaintext_len = 100;
    sym_decrypt(ciphertext, sizeof(ciphertext), plaintext, &out_plaintext_len);
    return 0;
}