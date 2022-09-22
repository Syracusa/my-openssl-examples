#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "testlib.h"
#include "sock.h"
#include "ossl_debug.h"

static int sendto_server(int sock, char *buf, int datalen)
{
    int sendres;
#if USE_DTLS

    static struct sockaddr_in server_addr;
    static int address_set = 0;

    if (address_set == 0)
    {
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        inet_aton(SERVER_IP, &server_addr.sin_addr);

        address_set = 1;
    }

    sendres = sendto(sock, buf, datalen, 0,
                         (struct sockaddr *)&server_addr,
                         sizeof(server_addr));
#else
    sendres = write(sock, buf, datalen);
#endif
    return sendres;
}

static int recvfrom_server(int sock, char *buf, int buflen)
{
    int len;
#if USE_DTLS
    len = recvfrom(sock, buf, buflen, 0, NULL, NULL);
#else
    len = read(sock, buf, buflen);
#endif
    return len;
}

static int
openssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    printf("Recv Peer Cert... Verifying... (preverify res %d)\n",
           preverify_ok);
    if (!preverify_ok)
    {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
        printf("verify error:num=%d:%s:depth=%d\n", err,
               X509_verify_cert_error_string(err), depth);
    }
    
    BIO *bio;
    char *pem = NULL;

    pem = x509_to_pem(X509_STORE_CTX_get0_cert(x509_ctx));

    if (!pem)
    {
        printf("No pem!\n");
    }
    else
    {
        bio = BIO_new(BIO_s_mem());
        if (bio)
        {
            char buffer[2048];
            int len;

            X509 *x509 = X509_STORE_CTX_get0_cert(x509_ctx);
            X509_NAME *x509name = X509_get_subject_name(x509);

            len = X509_NAME_print_ex(bio, x509name, 1,
                                     XN_FLAG_MULTILINE);
                                     
            BIO_read(bio, buffer, len);
            buffer[len] = '\0';
            printf("* * * \nPeer certificate received\n%s\n* * * \n", buffer);
            BIO_free(bio);
        }
        else
        {
            printf("failed to create certificate print membio\n");
        }

        free(pem);
    }

    return preverify_ok;
}

int main()
{
    SSL_CTX *ssl_context;

    init_ssl_context_from_file(&ssl_context,
                               "../cert/ca.cert.pem",
                               "../cert/ica.cert.pem",
                               "../cert/client.cert.pem",
                               "../cert/client.pem");

    SSL *ssl = SSL_new(ssl_context);
    enable_debuglog(ssl);

    int sock = BindSocket(TEST_SOCK_TYPE, CLIENT_PORT);
    
#if !USE_DTLS
    struct sockaddr_in server_addr;
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_aton(SERVER_IP, &server_addr.sin_addr);

    unsigned int addr_len = sizeof(server_addr);
    int cres;

    cres = connect(sock, (struct sockaddr*)&server_addr, addr_len);
    if (cres == 0){
        printf("TCP Connect Success\n");
    } else {
        printf("TCP Connect Fail %s\n", strerror(errno));
    }
#endif
    BIO *in_bio = BIO_new(BIO_s_mem());
    BIO *out_bio = BIO_new(BIO_s_mem());

    SSL_set_bio(ssl, in_bio, out_bio);

    SSL_set_verify(ssl,
                   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                   openssl_verify_callback);

    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, "Server");
    SSL_set1_host(ssl, "Server");

    int ret = SSL_do_handshake(ssl);
    printf("Client Handshake ret : %d\n", ret);


#define BUFLEN 4096
    char buf[BUFLEN];

    while (1)
    {
        int pending = BIO_ctrl_pending(out_bio);

        int readlen = 0;
        if (pending > 0)
        {
            readlen = BIO_read(out_bio, buf, sizeof(buf));
            printf("Client Pending %d, and read: %d\n", pending, readlen);
            sendto_server(sock, buf, readlen);
        }
        else
        {
            printf("Client Not Pending\n");
        }

        int recvlen = recvfrom_server(sock, buf, BUFLEN);
        int writelen = 0;
        if (recvlen > 0)
        {
            writelen = BIO_write(in_bio, buf, recvlen);
            printf("Write to bio(client) len %d\n", writelen);
        }
        else
        {
            printf("No data to write at bio\n");
        }

        if (!SSL_is_init_finished(ssl))
        {
            ret = SSL_do_handshake(ssl);
            ret = SSL_get_error(ssl, ret);

            printf("Handshake io res : %d(%s)\n",
                   ret, ssl_io_errcode_sting(ret));

            ERR_print_errors_fp(stdout);

            printf("Do some handshake(client) ret:%d\n", ret);
        }
        else
        {
            printf("SSL Handshake done... Current Cipher : %s\n",
                   SSL_get_cipher_name(ssl));
            char writebuf[100];
            strcpy(writebuf, "I'm client \n\0");
            SSL_write(ssl, writebuf, strlen(writebuf) + 1);

            int ssl_readlen = SSL_read(ssl, buf, sizeof(buf));
            if (ssl_readlen > 0)
            {
                printf("Recvfrom server : %s\n", buf);
            }
        }
        sleep(1);
    }

    printf("Done\n");
    return 0;
}