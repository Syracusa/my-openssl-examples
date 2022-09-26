#ifndef DTLSTEST_OSSL_DEBUG
#define DTLSTEST_OSSL_DEBUG

#include <openssl/ssl.h>

void enable_debuglog(SSL* ssl);

#endif