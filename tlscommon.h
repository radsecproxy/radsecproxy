/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2016, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ASN1_STRING_get0_data(o) ((o)->data)
#define ASN1_STRING_length(o) ((o)->length)
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
    pthread_mutex_t lock;
};

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
struct tls *tlsgettls(char *alt1, char *alt2);
SSL_CTX *tlsgetctx(uint8_t type, struct tls *t);
X509 *verifytlscert(SSL *ssl);
int verifyconfcert(X509 *cert, struct clsrvconf *conf);
int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
int addmatchcertattr(struct clsrvconf *conf);
void tlsreloadcrls();
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
