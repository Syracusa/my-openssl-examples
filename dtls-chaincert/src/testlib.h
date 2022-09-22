#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#if USE_DTLS
#define TEST_SOCK_TYPE SOCK_DGRAM
#else
#define TEST_SOCK_TYPE SOCK_STREAM
#endif

// #define SERVER_IP "192.168.1.104"
// #define CLIENT_IP "192.168.1.211"

#define SERVER_IP "127.0.0.1"
#define CLIENT_IP "127.0.0.1"

#define SERVER_PORT 35966
#define CLIENT_PORT 35967

char *ssl_io_errcode_sting(int code);

void init_ssl_context_from_file(SSL_CTX **ssl_ctx,
                                char *rootcacertfile,
                                char *cacertfile,
                                char *certfile,
                                char *pkeyfile);

char *x509_to_pem(X509 *x509);