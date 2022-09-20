#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#define SERVER_UDP_PORT 5111
#define CLIENT_UDP_PORT 5112

char *ssl_io_errcode_sting(int code);

void init_ssl_context_from_file(SSL_CTX **ssl_ctx,
                                char *rootcacertfile,
                                char *cacertfile,
                                char *certfile,
                                char *pkeyfile);

char *x509_to_pem(X509 *x509);