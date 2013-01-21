/* Copyright (c) 2007-2009, UNINETT AS */
/* See LICENSE for licensing information. */

#include <netinet/in.h>
#include <openssl/ssl.h>

#if defined (__cplusplus)
extern "C" {
#endif

struct tls {
    char *name;
    char *cacertfile;
    char *cacertpath;
    char *certfile;
    char *certkeyfile;
    char *certkeypwd;
    uint8_t crlcheck;
    char **policyoids;
    uint32_t cacheexpiry;
    uint32_t tlsexpiry;
    uint32_t dtlsexpiry;
    X509_VERIFY_PARAM *vpm;
    SSL_CTX *tlsctx;
    SSL_CTX *dtlsctx;
};

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
void ssl_init();
struct tls *tlsgettls(char *alt1, char *alt2);
SSL_CTX *tlsgetctx(uint8_t type, struct tls *t);
X509 *verifytlscert(SSL *ssl);
int subjectaltnameaddr(X509 *cert, int family, const struct in6_addr *addr);
int subjectaltnameregexp(X509 *cert, int type, const char *exact,  const regex_t *regex);
int cnregexp(X509 *cert, const char *exact, const regex_t *regex);
int verifyconfcert(X509 *cert, struct clsrvconf *conf);
#endif

#if defined (__cplusplus)
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
