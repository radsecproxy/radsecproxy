/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2016, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#ifndef _TLSCOMMON_H
#define _TLSCOMMON_H

#include <openssl/ssl.h>
#include "hostport.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ASN1_STRING_get0_data(o) ((o)->data)
#define ASN1_STRING_length(o) ((o)->length)
#endif

#define RADSEC_TLS_EX_INDEX_TLSCONF (10)
#define RADSEC_TLS_EX_INDEX_STORE (11)

struct tls {
    char *name;
    char *cacertfile;
    char *cacertpath;
    char *certfile;
    char *certkeyfile;
    char *certkeypwd;
    uint8_t crlcheck;
    uint8_t ocspcheck;
    uint8_t ocsp_ignore_empty_url;
    uint8_t ocsp_softfail;
    uint32_t ocsp_timeout;
    uint32_t ocsp_check_depth;
    uint8_t ocsp_caching;
    uint32_t ocsp_max_cache_time;
    uint8_t ocsp_stapling_server;
    uint8_t ocsp_stapling_client;
    OCSP_RESPONSE *ocsp_cert_staple;
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

extern int RSP_EX_DATA_CONFIG;
extern int RSP_EX_DATA_CONFIG_LIST;

void sslinit(void);
struct tls *tlsgettls(char *alt1, char *alt2);
struct tls *tlsgetdefaultpsk(void);
SSL_CTX *tlsgetctx(uint8_t type, struct tls *t);
X509 *verifytlscert(SSL *ssl);
int verifyconfcert(X509 *cert, struct clsrvconf *conf, struct hostportres *);
char *getcertsubject(X509 *cert);
int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
int addmatchcertattr(struct clsrvconf *conf, const char *match);
void freematchcertattr(struct clsrvconf *conf);
void tlsreload(void);
int tlssetsni(SSL *ssl, char *sni);
int sslconnecttimeout(SSL *ssl, int timeout);
int sslaccepttimeout (SSL *ssl, int timeout);
int sslreadtimeout(SSL *ssl, unsigned char *buf, int num, int timeout, pthread_mutex_t *lock);
int sslwrite(SSL *ssl, void *buf, int num, uint8_t blocking);
int radtlsget(SSL *ssl, int timeout, pthread_mutex_t *lock, uint8_t **buf);
void tlsserverrd(struct client *client);

#endif

#endif /*_TLSCOMMON_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
