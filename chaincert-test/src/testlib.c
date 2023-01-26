/* testlib.c */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "testlib.h"

#define USE_ARIA128 1

char *ssl_io_errcode_sting(int code)
{
    switch (code)
    {
    case SSL_ERROR_NONE:
        return "SSL_ERROR_NONE";
        break;
    case SSL_ERROR_SSL:
        return "SSL_ERROR_SSL";
        break;
    case SSL_ERROR_WANT_READ:
        return "SSL_ERROR_WANT_READ";
        break;
    case SSL_ERROR_WANT_WRITE:
        return "SSL_ERROR_WANT_WRITE";
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        return "SSL_ERROR_WANT_X509_LOOKUP";
        break;
    case SSL_ERROR_SYSCALL:
        return "SSL_ERROR_SYSCALL";
        break;
    case SSL_ERROR_ZERO_RETURN:
        return "SSL_ERROR_ZERO_RETURN ";
        break;
    case SSL_ERROR_WANT_CONNECT:
        return "SSL_ERROR_WANT_CONNECT";
        break;
    case SSL_ERROR_WANT_ACCEPT:
        return "SSL_ERROR_WANT_ACCEPT";
        break;
    default:
        return "Unknown_ERR";
        break;
    }
}

static void
add_trust_store_ca_cert_file(X509_STORE *trust_store, char *cacertfile)
{
    X509 *x509;
    FILE *f = fopen(cacertfile, "r");

    if (f != NULL){
        x509 = PEM_read_X509(f, NULL, NULL, NULL);

        if (x509)
        {
            X509_STORE_add_cert(trust_store, x509);
            fprintf(stderr,
                    "Successfully add CA Certificate from file %s\n",
                    cacertfile);
        }
        else
        {
            fprintf(stderr,
                    "Fail to add CA Certificate from file %s\n",
                    cacertfile);
        }
        fclose(f);
    } else {    
        fprintf(stderr,
                "No file named %s\n",
                cacertfile);
    }   

}

static void ossl_pick_and_prt_err()
{
    /* If any non-fatal issues happened, print them out and carry on */
    if (ERR_peek_error())
    {
        ERR_print_errors_fp(stdout);
        ERR_clear_error();
    }
}

void init_ssl_context_from_file(SSL_CTX **ssl_ctx,
                                char *rootcacertfile,
                                char *cacertfile,
                                char *certfile,
                                char *pkeyfile)
{
#if USE_DTLS
    SSL_CTX *ssl_context = SSL_CTX_new(DTLS_method());
    printf("USE DTLS\n");
#else
    SSL_CTX *ssl_context = SSL_CTX_new(TLS_method());
    printf("USE TLS\n");
#endif

    SSL_CTX_set_max_proto_version(ssl_context, TLS1_2_VERSION);

    if (!ssl_context)
    {
        printf("Error creating SSL Context\n");
    }

    X509_STORE *trust_store = X509_STORE_new();
    ossl_pick_and_prt_err();

    SSL_CTX_set_verify_depth(ssl_context, 2);
#if USE_ARIA128
    SSL_CTX_set_cipher_list(ssl_context,
                            "ARIA");
#else
    SSL_CTX_set_cipher_list(ssl_context,
                            "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
#endif

    SSL_CTX_set_cert_store(ssl_context, trust_store);
    SSL_CTX_set_read_ahead(ssl_context, 1);

    if (cacertfile){
        add_trust_store_ca_cert_file(trust_store, cacertfile);
    } else {
        fprintf(stderr, "Use root certificate as ca certificate\n");
    }
    add_trust_store_ca_cert_file(trust_store, rootcacertfile);

    int res = SSL_CTX_use_certificate_file(ssl_context,
                                           certfile,
                                           SSL_FILETYPE_PEM);
    if (1 != res)
    {
        printf("SSL_CTX_use_certificate_file() Error res %d\n", res);
        ERR_print_errors_fp(stdout);
        exit(2);
    }

    res = SSL_CTX_use_PrivateKey_file(ssl_context,
                                      pkeyfile,
                                      SSL_FILETYPE_PEM);

    if (1 != res)
    {
        printf("SSL_CTX_use_PrivateKey_file() Error\n");
        ERR_print_errors_fp(stdout);
        exit(2);
    }

    if (!SSL_CTX_check_private_key(ssl_context))
    {
        printf("invalid private key\n");
        ERR_print_errors_fp(stdout);
        exit(2);
    }

    *ssl_ctx = ssl_context;
}

#define BIO_BUFFER_SIZE 4096
char *x509_to_pem(X509 *x509)
{
    BIO *bio;
    char buffer[BIO_BUFFER_SIZE] = {0};
    char *pem = NULL;

    bio = BIO_new(BIO_s_mem());

    PEM_write_bio_X509(bio, (X509 *)x509);
    int len = BIO_read(bio, buffer, BIO_BUFFER_SIZE);

    pem = malloc(len * sizeof(char));
    memcpy(pem, buffer, len);

    BIO_free(bio);
    return pem;
}