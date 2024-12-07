/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2016, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#ifndef _TLSCOMMON_H
#define _TLSCOMMON_H

#include "hostport.h"
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ASN1_STRING_get0_data(o) ((o)->data)
#define ASN1_STRING_length(o) ((o)->length)
#endif

#define RSP_KEYLOG_ENV "SSLKEYLOGFILE"

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
    int cacheexpiry;
    int tlsminversion;
    int tlsmaxversion;
    int dtlsminversion;
    int dtlsmaxversion;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY *dhparam;
#else
    DH *dhparam;
#endif
    time_t tlsexpiry;
    time_t dtlsexpiry;
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
struct tls *tlsgettls(char *conf);
struct tls *tlsgetdefaultpsk(void);
SSL_CTX *tlsgetctx(uint8_t type, struct tls *t);
X509 *verifytlscert(SSL *ssl);
int verifyconfcert(X509 *cert, struct clsrvconf *conf, struct hostportres *, const char *nairealm);
char *getcertsubject(X509 *cert);
int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
int addmatchcertattr(struct clsrvconf *conf, const char *match);
void freematchcertattr(struct clsrvconf *conf);
void tlsreload(void);
int tlssetsni(SSL *ssl, char *sni);
int sslconnecttimeout(SSL *ssl, int timeout);
int sslaccepttimeout(SSL *ssl, int timeout);
int sslreadtimeout(SSL *ssl, unsigned char *buf, int num, int timeout, pthread_mutex_t *lock);
int sslwrite(SSL *ssl, void *buf, int num, uint8_t blocking);
int radtlsget(SSL *ssl, int timeout, pthread_mutex_t *lock, uint8_t **buf);
void tlsserverrd(struct client *client);
void terminateinvalidserver(struct server *srv);
void terminateinvalidclient(struct client *cli);

#endif

#endif /*_TLSCOMMON_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
