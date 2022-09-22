/* s_cb.c s_server.c...*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

typedef struct string_int_pair_st {
    const char *name;
    int retval;
} OPT_PAIR, STRINT_PAIR;

static const char *lookup(int val, const STRINT_PAIR* list, const char* def)
{
    for ( ; list->name; ++list)
        if (list->retval == val)
            return list->name;
    return def;
}

static STRINT_PAIR ssl_versions[] = {
    {"SSL 3.0", SSL3_VERSION},
    {"TLS 1.0", TLS1_VERSION},
    {"TLS 1.1", TLS1_1_VERSION},
    {"TLS 1.2", TLS1_2_VERSION},
    {"TLS 1.3", TLS1_3_VERSION},
    {"DTLS 1.0", DTLS1_VERSION},
    {"DTLS 1.2", DTLS1_2_VERSION},
    {"DTLS 1.0 (bad)", DTLS1_BAD_VER},
    {NULL}
};

static STRINT_PAIR alert_types[] = {
    {" close_notify", 0},
    {" end_of_early_data", 1},
    {" unexpected_message", 10},
    {" bad_record_mac", 20},
    {" decryption_failed", 21},
    {" record_overflow", 22},
    {" decompression_failure", 30},
    {" handshake_failure", 40},
    {" bad_certificate", 42},
    {" unsupported_certificate", 43},
    {" certificate_revoked", 44},
    {" certificate_expired", 45},
    {" certificate_unknown", 46},
    {" illegal_parameter", 47},
    {" unknown_ca", 48},
    {" access_denied", 49},
    {" decode_error", 50},
    {" decrypt_error", 51},
    {" export_restriction", 60},
    {" protocol_version", 70},
    {" insufficient_security", 71},
    {" internal_error", 80},
    {" inappropriate_fallback", 86},
    {" user_canceled", 90},
    {" no_renegotiation", 100},
    {" missing_extension", 109},
    {" unsupported_extension", 110},
    {" certificate_unobtainable", 111},
    {" unrecognized_name", 112},
    {" bad_certificate_status_response", 113},
    {" bad_certificate_hash_value", 114},
    {" unknown_psk_identity", 115},
    {" certificate_required", 116},
    {NULL}
};

static STRINT_PAIR handshakes[] = {
    {", HelloRequest", SSL3_MT_HELLO_REQUEST},
    {", ClientHello", SSL3_MT_CLIENT_HELLO},
    {", ServerHello", SSL3_MT_SERVER_HELLO},
    {", HelloVerifyRequest", DTLS1_MT_HELLO_VERIFY_REQUEST},
    {", NewSessionTicket", SSL3_MT_NEWSESSION_TICKET},
    {", EndOfEarlyData", SSL3_MT_END_OF_EARLY_DATA},
    {", EncryptedExtensions", SSL3_MT_ENCRYPTED_EXTENSIONS},
    {", Certificate", SSL3_MT_CERTIFICATE},
    {", ServerKeyExchange", SSL3_MT_SERVER_KEY_EXCHANGE},
    {", CertificateRequest", SSL3_MT_CERTIFICATE_REQUEST},
    {", ServerHelloDone", SSL3_MT_SERVER_DONE},
    {", CertificateVerify", SSL3_MT_CERTIFICATE_VERIFY},
    {", ClientKeyExchange", SSL3_MT_CLIENT_KEY_EXCHANGE},
    {", Finished", SSL3_MT_FINISHED},
    {", CertificateUrl", SSL3_MT_CERTIFICATE_URL},
    {", CertificateStatus", SSL3_MT_CERTIFICATE_STATUS},
    {", SupplementalData", SSL3_MT_SUPPLEMENTAL_DATA},
    {", KeyUpdate", SSL3_MT_KEY_UPDATE},
#ifndef OPENSSL_NO_NEXTPROTONEG
    {", NextProto", SSL3_MT_NEXT_PROTO},
#endif
    {", MessageHash", SSL3_MT_MESSAGE_HASH},
    {NULL}
};

void msg_cb(int write_p, int version, int content_type, const void *buf,
            size_t len, SSL *ssl, void *arg)
{
    const char *str_write_p = write_p ? ">>>" : "<<<";
    char tmpbuf[128];
    const char *str_version, *str_content_type = "", *str_details1 = "", *str_details2 = "";
    const unsigned char* bp = buf;

    str_version = lookup(version, ssl_versions, "???");

    switch (content_type) {
    case SSL3_RT_CHANGE_CIPHER_SPEC:
        /* type 20 */
        str_content_type = ", ChangeCipherSpec";
        break;
    case SSL3_RT_ALERT:
        /* type 21 */
        str_content_type = ", Alert";
        str_details1 = ", ???";
        if (len == 2) {
            switch (bp[0]) {
            case 1:
                str_details1 = ", warning";
                break;
            case 2:
                str_details1 = ", fatal";
                break;
            }
            str_details2 = lookup((int)bp[1], alert_types, " ???");
        }
        break;
    case SSL3_RT_HANDSHAKE:
        /* type 22 */
        str_content_type = ", Handshake";
        str_details1 = "???";
        if (len > 0)
            str_details1 = lookup((int)bp[0], handshakes, "???");
        break;
    case SSL3_RT_APPLICATION_DATA:
        /* type 23 */
        str_content_type = ", ApplicationData";
        break;
    case SSL3_RT_HEADER:
        /* type 256 */
        str_content_type = ", RecordHeader";
        break;
    case SSL3_RT_INNER_CONTENT_TYPE:
        /* type 257 */
        str_content_type = ", InnerContent";
        break;
    default:
        BIO_snprintf(tmpbuf, sizeof(tmpbuf)-1, ", Unknown (content_type=%d)", content_type);
        str_content_type = tmpbuf;
    }


    struct timespec ct;
    clock_gettime(CLOCK_REALTIME, &ct);
    printf("[%4ld:%4ld]", ct.tv_sec % 1000, ct.tv_nsec / 1000000);

    printf("%s %s%s [length %04lx]%s%s\n", str_write_p, str_version,
               str_content_type, (unsigned long)len, str_details1,
               str_details2);

    if (len > 0) {
        size_t num, i;

        printf("   ");
        num = len;
        for (i = 0; i < num; i++) {
            if (i % 16 == 0 && i > 0)
                printf("\n   ");
            printf(" %02x", ((const unsigned char *)buf)[i]);
        }
        if (i < len)
            printf(" ...");
        printf("\n");
    }
    fflush(stdout);
}

void enable_debuglog(SSL* ssl){
    SSL_set_msg_callback(ssl, msg_cb);
}