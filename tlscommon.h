/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2016, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <openssl/ssl.h>
#include "hostport.h"

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
    char *cipherlist;
    char *ciphersuites;
    uint32_t cacheexpiry;
    int tlsminversion;
    int tlsmaxversion;
    int dtlsminversion;
    int dtlsmaxversion;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY* dhparam;
#else
    DH *dhparam;
#endif
    uint32_t tlsexpiry;
    uint32_t dtlsexpiry;
    X509_VERIFY_PARAM *vpm;
    SSL_CTX *tlsctx;
    SSL_CTX *dtlsctx;
	SSL *dtlssslprep;
    pthread_mutex_t lock;
};

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
void sslinit();
struct tls *tlsgettls(char *alt1, char *alt2);
SSL_CTX *tlsgetctx(uint8_t type, struct tls *t);
X509 *verifytlscert(SSL *ssl);
int verifyconfcert(X509 *cert, struct clsrvconf *conf, struct hostportres *);
char *getcertsubject(X509 *cert);
int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
int addmatchcertattr(struct clsrvconf *conf, const char *match);
void freematchcertattr(struct clsrvconf *conf);
void tlsreloadcrls();
int tlssetsni(SSL *ssl, char *sni);
int sslconnecttimeout(SSL *ssl, int timeout);
int sslaccepttimeout (SSL *ssl, int timeout);
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
