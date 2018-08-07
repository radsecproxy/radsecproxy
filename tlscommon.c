/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2011,2015-2016, NORDUnet A/S */
/* See LICENSE for licensing information. */

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <regex.h>
#include <libgen.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>
#include "debug.h"
#include "hash.h"
#include "util.h"
#include "hostport.h"
#include "radsecproxy.h"

static struct hash *tlsconfs = NULL;

#define COOKIE_SECRET_LENGTH 16
static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
static uint8_t cookie_secret_initialized = 0;


/* callbacks for making OpenSSL < 1.1 thread safe */
#if OPENSSL_VERSION_NUMBER < 0x10100000
static pthread_mutex_t *ssl_locks = NULL;

unsigned long ssl_thread_id() {
    return (unsigned long)pthread_self();
}

void ssl_locking_callback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
       pthread_mutex_lock(&ssl_locks[type]);
    else
       pthread_mutex_unlock(&ssl_locks[type]);
}
#endif

void sslinit() {
#if OPENSSL_VERSION_NUMBER < 0x10100000
    int i;

    SSL_library_init();

    ssl_locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (!ssl_locks)
        debugx(1, DBG_ERR, "malloc failed");

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&ssl_locks[i], NULL);
    }
    CRYPTO_set_id_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_locking_callback);
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
}

static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    int pwdlen = strlen(userdata);
    if (rwflag != 0 || pwdlen > size) /* not for decryption or too large */
	return 0;
    memcpy(buf, userdata, pwdlen);
    return pwdlen;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx) {
    char *buf = NULL;
    X509 *err_cert;
    int err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    if (depth > MAX_CERT_DEPTH) {
	ok = 0;
	err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	X509_STORE_CTX_set_error(ctx, err);
    }

    if (!ok) {
	if (err_cert)
	    buf = X509_NAME_oneline(X509_get_subject_name(err_cert), NULL, 0);
	debug(DBG_WARN, "verify error: num=%d:%s:depth=%d:%s", err, X509_verify_cert_error_string(err), depth, buf ? buf : "");
	free(buf);
	buf = NULL;

	switch (err) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	    if (err_cert) {
		buf = X509_NAME_oneline(X509_get_issuer_name(err_cert), NULL, 0);
		if (buf) {
		    debug(DBG_WARN, "\tIssuer=%s", buf);
		    free(buf);
		    buf = NULL;
		}
	    }
	    break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	    debug(DBG_WARN, "\tCertificate not yet valid");
	    break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	    debug(DBG_WARN, "Certificate has expired");
	    break;
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	    debug(DBG_WARN, "Certificate no longer valid (after notAfter)");
	    break;
	case X509_V_ERR_NO_EXPLICIT_POLICY:
	    debug(DBG_WARN, "No Explicit Certificate Policy");
	    break;
	}
    }
#ifdef DEBUG
    printf("certificate verify returns %d\n", ok);
#endif
    return ok;
}

static int cookie_calculate_hash(struct sockaddr *peer, time_t time, uint8_t *result, unsigned int *resultlength) {
    uint8_t *buf;
    int length;

    length = SOCKADDRP_SIZE(peer) + sizeof(time_t);
    buf = OPENSSL_malloc(length);
    if (!buf) {
        debug(DBG_ERR, "cookie_calculate_hash: malloc failed");
        return 0;
    }

    memcpy(buf, &time, sizeof(time_t));
    memcpy(buf+sizeof(time_t), peer, SOCKADDRP_SIZE(peer));

    HMAC(EVP_sha256(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
         buf, length, result, resultlength);
    OPENSSL_free(buf);
    return 1;
}

static int cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    struct sockaddr_storage peer;
    struct timeval now;
    uint8_t result[EVP_MAX_MD_SIZE];
    unsigned int resultlength;

    if (!cookie_secret_initialized) {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
            debugx(1,DBG_ERR, "cookie_generate_cg: error generating random secret");
        cookie_secret_initialized = 1;
    }

    if (BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer) <= 0)
        return 0;
    gettimeofday(&now, NULL);
    if (!cookie_calculate_hash((struct sockaddr *)&peer, now.tv_sec, result, &resultlength))
        return 0;

    memcpy(cookie, &now.tv_sec, sizeof(time_t));
    memcpy(cookie + sizeof(time_t), result, resultlength);
    *cookie_len = resultlength + sizeof(time_t);

    return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static int cookie_verify_cb(SSL *ssl, unsigned char *cookie, unsigned int cookie_len) {
#else
static int cookie_verify_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
#endif
    struct sockaddr_storage peer;
    struct timeval now;
    time_t cookie_time;
    uint8_t result[EVP_MAX_MD_SIZE];
    unsigned int resultlength;

    if (!cookie_secret_initialized)
        return 0;

    if (cookie_len < sizeof(time_t)) {
        debug(DBG_DBG, "cookie_verify_cb: cookie too short. ignoring.");
        return 0;
    }

    gettimeofday(&now, NULL);
    cookie_time = *(time_t *)cookie;
    if (now.tv_sec - cookie_time > 5) {
        debug(DBG_DBG, "cookie_verify_cb: cookie invalid or older than 5s. ignoring.");
        return 0;
    }

    if (BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer) <= 0)
        return 0;
    if (!cookie_calculate_hash((struct sockaddr *)&peer, cookie_time, result, &resultlength))
        return 0;

    if (resultlength + sizeof(time_t) != cookie_len) {
        debug(DBG_DBG, "cookie_verify_cb: invalid cookie length. ignoring.");
        return 0;
    }

    if (memcmp(cookie + sizeof(time_t), result, resultlength)) {
        debug(DBG_DBG, "cookie_verify_cb: cookie not valid. ignoring.");
        return 0;
    }
    return 1;
}

#ifdef DEBUG
static void ssl_info_callback(const SSL *ssl, int where, int ret) {
    const char *s;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
	s = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
	s = "SSL_accept";
    else
	s = "undefined";

    if (where & SSL_CB_LOOP)
	debug(DBG_DBG, "%s:%s\n", s, SSL_state_string_long(ssl));
    else if (where & SSL_CB_ALERT) {
	s = (where & SSL_CB_READ) ? "read" : "write";
	debug(DBG_DBG, "SSL3 alert %s:%s:%s\n", s, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT) {
	if (ret == 0)
	    debug(DBG_DBG, "%s:failed in %s\n", s, SSL_state_string_long(ssl));
	else if (ret < 0)
	    debug(DBG_DBG, "%s:error in %s\n", s, SSL_state_string_long(ssl));
    }
}
#endif

static X509_VERIFY_PARAM *createverifyparams(char **poids) {
    X509_VERIFY_PARAM *pm;
    ASN1_OBJECT *pobject;
    int i;

    pm = X509_VERIFY_PARAM_new();
    if (!pm)
	return NULL;

    for (i = 0; poids[i]; i++) {
	pobject = OBJ_txt2obj(poids[i], 0);
	if (!pobject) {
	    X509_VERIFY_PARAM_free(pm);
	    return NULL;
	}
	X509_VERIFY_PARAM_add0_policy(pm, pobject);
    }

    X509_VERIFY_PARAM_set_flags(pm, X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY);
    return pm;
}

static int tlsaddcacrl(SSL_CTX *ctx, struct tls *conf) {
    STACK_OF(X509_NAME) *calist;
    X509_STORE *x509_s;
    unsigned long error;

    SSL_CTX_set_cert_store(ctx, X509_STORE_new());
    if (!SSL_CTX_load_verify_locations(ctx, conf->cacertfile, conf->cacertpath)) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
	debug(DBG_ERR, "tlsaddcacrl: Error updating TLS context %s", conf->name);
	return 0;
    }

    calist = conf->cacertfile ? SSL_load_client_CA_file(conf->cacertfile) : NULL;
    if (!conf->cacertfile || calist) {
	if (conf->cacertpath) {
	    if (!calist)
		calist = sk_X509_NAME_new_null();
	    if (!SSL_add_dir_cert_subjects_to_stack(calist, conf->cacertpath)) {
		sk_X509_NAME_free(calist);
		calist = NULL;
	    }
	}
    }
    if (!calist) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
	debug(DBG_ERR, "tlsaddcacrl: Error adding CA subjects in TLS context %s", conf->name);
	return 0;
    }
    ERR_clear_error(); /* add_dir_cert_subj returns errors on success */
    SSL_CTX_set_client_CA_list(ctx, calist);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
    SSL_CTX_set_verify_depth(ctx, MAX_CERT_DEPTH + 1);
    SSL_CTX_set_cookie_generate_cb(ctx, cookie_generate_cb);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify_cb);

    if (conf->crlcheck || conf->vpm) {
	x509_s = SSL_CTX_get_cert_store(ctx);
	if (conf->crlcheck)
	    X509_STORE_set_flags(x509_s, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	if (conf->vpm)
	    X509_STORE_set1_param(x509_s, conf->vpm);
    }

    debug(DBG_DBG, "tlsaddcacrl: updated TLS context %s", conf->name);
    return 1;
}

static SSL_CTX *tlscreatectx(uint8_t type, struct tls *conf) {
    SSL_CTX *ctx = NULL;
    unsigned long error;

    switch (type) {
#ifdef RADPROT_TLS
    case RAD_TLS:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        /* TLS_method() was introduced in OpenSSL 1.1.0. */
	ctx = SSL_CTX_new(TLS_method());
#else
        /* No TLS_method(), use SSLv23_method() and disable SSLv2 and SSLv3. */
        ctx = SSL_CTX_new(SSLv23_method());
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#endif
#ifdef DEBUG
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
#endif
	break;
#endif
#ifdef RADPROT_DTLS
    case RAD_DTLS:
#if OPENSSL_VERSION_NUMBER >= 0x10002000
        /* DTLS_method() seems to have been introduced in OpenSSL 1.0.2. */
	ctx = SSL_CTX_new(DTLS_method());
#else
	ctx = SSL_CTX_new(DTLSv1_method());
#endif
#ifdef DEBUG
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
#endif
	SSL_CTX_set_read_ahead(ctx, 1);
	break;
#endif
    }
    if (!ctx) {
	debug(DBG_ERR, "tlscreatectx: Error initialising SSL/TLS in TLS context %s", conf->name);
	return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    {
    long sslversion = SSLeay();
    if (sslversion < 0x00908100L ||
        (sslversion >= 0x10000000L && sslversion < 0x10000020L)) {
        debug(DBG_WARN, "%s: %s seems to be of a version with a "
	      "certain security critical bug (fixed in OpenSSL 0.9.8p and "
	      "1.0.0b).  Disabling OpenSSL session caching for context %p.",
	      __func__, SSLeay_version(SSLEAY_VERSION), ctx);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }
    }
#endif

    if (conf->certkeypwd) {
	SSL_CTX_set_default_passwd_cb_userdata(ctx, conf->certkeypwd);
	SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    }
    if (!SSL_CTX_use_certificate_chain_file(ctx, conf->certfile) ||
	!SSL_CTX_use_PrivateKey_file(ctx, conf->certkeyfile, SSL_FILETYPE_PEM) ||
	!SSL_CTX_check_private_key(ctx)) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
	debug(DBG_ERR, "tlscreatectx: Error initialising SSL/TLS in TLS context %s", conf->name);
	SSL_CTX_free(ctx);
	return NULL;
    }

    if (conf->policyoids) {
	if (!conf->vpm) {
	    conf->vpm = createverifyparams(conf->policyoids);
	    if (!conf->vpm) {
		debug(DBG_ERR, "tlscreatectx: Failed to add policyOIDs in TLS context %s", conf->name);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	}
    }

    if (!tlsaddcacrl(ctx, conf)) {
	if (conf->vpm) {
	    X509_VERIFY_PARAM_free(conf->vpm);
	    conf->vpm = NULL;
	}
	SSL_CTX_free(ctx);
	return NULL;
    }

    debug(DBG_DBG, "tlscreatectx: created TLS context %s", conf->name);
    return ctx;
}

struct tls *tlsgettls(char *alt1, char *alt2) {
    struct tls *t;

    t = hash_read(tlsconfs, alt1, strlen(alt1));
    if (!t)
	t = hash_read(tlsconfs, alt2, strlen(alt2));
    return t;
}

SSL_CTX *tlsgetctx(uint8_t type, struct tls *t) {
    struct timeval now;

    if (!t)
	return NULL;
    gettimeofday(&now, NULL);

    switch (type) {
#ifdef RADPROT_TLS
    case RAD_TLS:
	if (t->tlsexpiry && t->tlsctx) {
	    if (t->tlsexpiry < now.tv_sec) {
		t->tlsexpiry = now.tv_sec + t->cacheexpiry;
		tlsaddcacrl(t->tlsctx, t);
	    }
	}
	if (!t->tlsctx) {
	    t->tlsctx = tlscreatectx(RAD_TLS, t);
	    if (t->cacheexpiry)
		t->tlsexpiry = now.tv_sec + t->cacheexpiry;
	}
	return t->tlsctx;
#endif
#ifdef RADPROT_DTLS
    case RAD_DTLS:
	if (t->dtlsexpiry && t->dtlsctx) {
	    if (t->dtlsexpiry < now.tv_sec) {
		t->dtlsexpiry = now.tv_sec + t->cacheexpiry;
		tlsaddcacrl(t->dtlsctx, t);
	    }
	}
	if (!t->dtlsctx) {
	    t->dtlsctx = tlscreatectx(RAD_DTLS, t);
	    if (t->cacheexpiry)
		t->dtlsexpiry = now.tv_sec + t->cacheexpiry;
	}
	return t->dtlsctx;
#endif
    }
    return NULL;
}

void tlsreloadcrls() {
    struct tls *conf;
    struct hash_entry *entry;
    struct timeval now;

    debug (DBG_NOTICE, "reloading CRLs");

    gettimeofday(&now, NULL);

    for (entry = hash_first(tlsconfs); entry; entry = hash_next(entry)) {
	conf = (struct tls *)entry->data;
#ifdef RADPROT_TLS
	if (conf->tlsctx) {
	    if (conf->tlsexpiry)
		conf->tlsexpiry = now.tv_sec + conf->cacheexpiry;
	    tlsaddcacrl(conf->tlsctx, conf);
	}
#endif
#ifdef RADPROT_DTLS
	if (conf->dtlsctx) {
	    if (conf->dtlsexpiry)
		conf->dtlsexpiry = now.tv_sec + conf->cacheexpiry;
	    tlsaddcacrl(conf->dtlsctx, conf);
	}
#endif
    }
}

X509 *verifytlscert(SSL *ssl) {
    X509 *cert;
    unsigned long error;

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
	debug(DBG_ERR, "verifytlscert: basic validation failed");
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "verifytlscert: TLS: %s", ERR_error_string(error, NULL));
	return NULL;
    }

    cert = SSL_get_peer_certificate(ssl);
    if (!cert)
	debug(DBG_ERR, "verifytlscert: failed to obtain certificate");
    return cert;
}

static int subjectaltnameaddr(X509 *cert, int family, struct in6_addr *addr) {
    int loc, i, l, n, r = 0;
    char *v;
    X509_EXTENSION *ex;
    STACK_OF(GENERAL_NAME) *alt;
    GENERAL_NAME *gn;

    debug(DBG_DBG, "subjectaltnameaddr");

    loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (loc < 0)
	return r;

    ex = X509_get_ext(cert, loc);
    alt = X509V3_EXT_d2i(ex);
    if (!alt)
	return r;

    n = sk_GENERAL_NAME_num(alt);
    for (i = 0; i < n; i++) {
	gn = sk_GENERAL_NAME_value(alt, i);
	if (gn->type != GEN_IPADD)
	    continue;
	r = -1;
	v = (char *)ASN1_STRING_get0_data(gn->d.ia5);
	l = ASN1_STRING_length(gn->d.ia5);
	if (((family == AF_INET && l == sizeof(struct in_addr)) || (family == AF_INET6 && l == sizeof(struct in6_addr)))
	    && !memcmp(v, addr, l)) {
	    r = 1;
	    break;
	}
    }
    GENERAL_NAMES_free(alt);
    return r;
}

static int subjectaltnameregexp(X509 *cert, int type, char *exact,  regex_t *regex) {
    int loc, i, l, n, r = 0;
    char *s, *v, *fail = NULL, *tmp;
    X509_EXTENSION *ex;
    STACK_OF(GENERAL_NAME) *alt;
    GENERAL_NAME *gn;

    debug(DBG_DBG, "subjectaltnameregexp");

    loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (loc < 0)
	return r;

    ex = X509_get_ext(cert, loc);
    alt = X509V3_EXT_d2i(ex);
    if (!alt)
	return r;

    n = sk_GENERAL_NAME_num(alt);
    for (i = 0; i < n; i++) {
	gn = sk_GENERAL_NAME_value(alt, i);
	if (gn->type != type)
	    continue;
	r = -1;
	v = (char *)ASN1_STRING_get0_data(gn->d.ia5);
	l = ASN1_STRING_length(gn->d.ia5);
	if (l <= 0)
	    continue;
#ifdef DEBUG
	printfchars(NULL, gn->type == GEN_DNS ? "dns" : "uri", NULL, (uint8_t *) v, l);
#endif
	if (exact) {
	    if (memcmp(v, exact, l))
		continue;
	} else {
	    s = stringcopy((char *)v, l);
	    if (!s) {
		debug(DBG_ERR, "malloc failed");
		continue;
	    }
        debug(DBG_DBG, "subjectaltnameregex: matching %s", s);
        if (regexec(regex, s, 0, NULL, 0)) {
            tmp = fail;
            if (asprintf(&fail, "%s%s%s", tmp ? tmp : "", tmp ? ", " : "", s) >= 0)
                free(tmp);
            else
                fail = tmp;
            free(s);
            continue;
	    }
	    free(s);
	}
	r = 1;
	break;
    }
    if (r!=1)
        debug(DBG_WARN, "subjectaltnameregex: no matching Subject Alt Name %s found! (%s)",
            type == GEN_DNS ? "DNS" : "URI", fail);
    GENERAL_NAMES_free(alt);
    free(fail);
    return r;
}

static int cnregexp(X509 *cert, char *exact, regex_t *regex) {
    int loc, l;
    char *v, *s;
    X509_NAME *nm;
    X509_NAME_ENTRY *e;
    ASN1_STRING *t;

    nm = X509_get_subject_name(cert);
    loc = -1;
    for (;;) {
	loc = X509_NAME_get_index_by_NID(nm, NID_commonName, loc);
	if (loc == -1)
	    break;
	e = X509_NAME_get_entry(nm, loc);
	t = X509_NAME_ENTRY_get_data(e);
	v = (char *) ASN1_STRING_get0_data(t);
	l = ASN1_STRING_length(t);
	if (l < 0)
	    continue;
	if (exact) {
	    if (l == strlen(exact) && !strncasecmp(exact, v, l))
		return 1;
	} else {
	    s = stringcopy((char *)v, l);
	    if (!s) {
		debug(DBG_ERR, "malloc failed");
		continue;
	    }
	    if (regexec(regex, s, 0, NULL, 0)) {
		free(s);
		continue;
	    }
	    free(s);
	    return 1;
	}
    }
    return 0;
}

/* this is a bit sloppy, should not always accept match to any */
int certnamecheck(X509 *cert, struct list *hostports) {
    struct list_node *entry;
    struct hostportres *hp;
    int r;
    uint8_t type = 0; /* 0 for DNS, AF_INET for IPv4, AF_INET6 for IPv6 */
    struct in6_addr addr;

    for (entry = list_first(hostports); entry; entry = list_next(entry)) {
	hp = (struct hostportres *)entry->data;
	if (hp->prefixlen != 255) {
	    /* we disable the check for prefixes */
	    return 1;
	}
	if (inet_pton(AF_INET, hp->host, &addr))
	    type = AF_INET;
	else if (inet_pton(AF_INET6, hp->host, &addr))
	    type = AF_INET6;
	else
	    type = 0;

	r = type ? subjectaltnameaddr(cert, type, &addr) : subjectaltnameregexp(cert, GEN_DNS, hp->host, NULL);
	if (r) {
	    if (r > 0) {
		debug(DBG_DBG, "certnamecheck: Found subjectaltname matching %s %s", type ? "address" : "host", hp->host);
		return 1;
	    }
	    debug(DBG_WARN, "certnamecheck: No subjectaltname matching %s %s", type ? "address" : "host", hp->host);
	} else {
	    if (cnregexp(cert, hp->host, NULL)) {
		debug(DBG_DBG, "certnamecheck: Found cn matching host %s", hp->host);
		return 1;
	    }
	    debug(DBG_WARN, "certnamecheck: cn not matching host %s", hp->host);
	}
    }
    return 0;
}

int verifyconfcert(X509 *cert, struct clsrvconf *conf) {
    char *subject;
    int ok = 1;

    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    debug(DBG_DBG, "verifyconfcert: verify certificate for host %s, subject %s", conf->name, subject);
    if (conf->certnamecheck) {
        debug(DBG_DBG, "verifyconfcert: verify hostname");
        if (!certnamecheck(cert, conf->hostports)) {
            debug(DBG_DBG, "verifyconfcert: certificate name check failed for host %s", conf->name);
            ok = 0;
        }
    }
    if (conf->certcnregex) {
        debug(DBG_DBG, "verifyconfcert: matching CN regex %s", conf->matchcertattr);
        if (cnregexp(cert, NULL, conf->certcnregex) < 1) {
            debug(DBG_WARN, "verifyconfcert: CN not matching regex for host %s (%s)", conf->name, subject);
            ok = 0;
        }
    }
    if (conf->certuriregex) {
        debug(DBG_DBG, "verifyconfcert: matching subjectaltname URI regex %s", conf->matchcertattr);
        if (subjectaltnameregexp(cert, GEN_URI, NULL, conf->certuriregex) < 1) {
            debug(DBG_WARN, "verifyconfcert: subjectaltname URI not matching regex for host %s (%s)", conf->name, subject);
            ok = 0;
        }
    }
    free(subject);
    return ok;
}

int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    struct tls *conf;
    long int expiry = LONG_MIN;

    debug(DBG_DBG, "conftls_cb called for %s", block);

    conf = malloc(sizeof(struct tls));
    if (!conf) {
	debug(DBG_ERR, "conftls_cb: malloc failed");
	return 0;
    }
    memset(conf, 0, sizeof(struct tls));

    if (!getgenericconfig(cf, block,
			  "CACertificateFile", CONF_STR, &conf->cacertfile,
			  "CACertificatePath", CONF_STR, &conf->cacertpath,
			  "CertificateFile", CONF_STR, &conf->certfile,
			  "CertificateKeyFile", CONF_STR, &conf->certkeyfile,
			  "CertificateKeyPassword", CONF_STR, &conf->certkeypwd,
			  "CacheExpiry", CONF_LINT, &expiry,
			  "CRLCheck", CONF_BLN, &conf->crlcheck,
			  "PolicyOID", CONF_MSTR, &conf->policyoids,
			  NULL
	    )) {
	debug(DBG_ERR, "conftls_cb: configuration error in block %s", val);
	goto errexit;
    }
    if (!conf->certfile || !conf->certkeyfile) {
	debug(DBG_ERR, "conftls_cb: TLSCertificateFile and TLSCertificateKeyFile must be specified in block %s", val);
	goto errexit;
    }
    if (!conf->cacertfile && !conf->cacertpath) {
	debug(DBG_ERR, "conftls_cb: CA Certificate file or path need to be specified in block %s", val);
	goto errexit;
    }
    if (expiry != LONG_MIN) {
	if (expiry < 0) {
	    debug(DBG_ERR, "error in block %s, value of option CacheExpiry is %ld, may not be negative", val, expiry);
	    goto errexit;
	}
	conf->cacheexpiry = expiry;
    }

    conf->name = stringcopy(val, 0);
    if (!conf->name) {
	debug(DBG_ERR, "conftls_cb: malloc failed");
	goto errexit;
    }
    pthread_mutex_init(&conf->lock, NULL);

    if (!tlsconfs)
	tlsconfs = hash_create();
    if (!hash_insert(tlsconfs, val, strlen(val), conf)) {
	debug(DBG_ERR, "conftls_cb: malloc failed");
	goto errexit;
    }
    if (!tlsgetctx(RAD_TLS, conf))
	debug(DBG_ERR, "conftls_cb: error creating ctx for TLS block %s", val);
    debug(DBG_DBG, "conftls_cb: added TLS block %s", val);
    return 1;

errexit:
    free(conf->cacertfile);
    free(conf->cacertpath);
    free(conf->certfile);
    free(conf->certkeyfile);
    free(conf->certkeypwd);
    freegconfmstr(conf->policyoids);
    free(conf);
    return 0;
}

int addmatchcertattr(struct clsrvconf *conf) {
    char *v;
    regex_t **r;

    if (!strncasecmp(conf->matchcertattr, "CN:/", 4)) {
	r = &conf->certcnregex;
	v = conf->matchcertattr + 4;
    } else if (!strncasecmp(conf->matchcertattr, "SubjectAltName:URI:/", 20)) {
	r = &conf->certuriregex;
	v = conf->matchcertattr + 20;
    } else
	return 0;
    if (!*v)
	return 0;
    /* regexp, remove optional trailing / if present */
    if (v[strlen(v) - 1] == '/')
	v[strlen(v) - 1] = '\0';
    if (!*v)
	return 0;

    *r = malloc(sizeof(regex_t));
    if (!*r) {
	debug(DBG_ERR, "malloc failed");
	return 0;
    }
    if (regcomp(*r, v, REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
	free(*r);
	*r = NULL;
	debug(DBG_ERR, "failed to compile regular expression %s", v);
	return 0;
    }
    return 1;
}

int sslaccepttimeout (SSL *ssl, int timeout) {
    int socket, origflags, ndesc, r = -1, sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    struct pollfd fds[1];
    uint8_t want_write = 1;

    socket = SSL_get_fd(ssl);
    origflags = fcntl(socket, F_GETFL, 0);
    if (origflags == -1) {
        debugerrno(errno, DBG_WARN, "Failed to get flags");
        return -1;
    }
    if (fcntl(socket, F_SETFL, origflags | O_NONBLOCK) == -1) {
        debugerrno(errno, DBG_WARN, "Failed to set O_NONBLOCK");
        return -1;
    }

    while (r < 1) {
        fds[0].fd = socket;
        fds[0].events = POLLIN;
        if (want_write) {
            fds[0].events |= POLLOUT;
            want_write = 0;
        }
        if ((ndesc = poll(fds, 1, timeout * 1000)) < 1) {
            if (ndesc == 0)
                debug(DBG_DBG, "sslaccepttimeout: timeout during SSL_accept");
            else
                debugerrno(errno, DBG_DBG, "sslaccepttimeout: poll error");
            break;
        }

        if (fds[0].revents & POLLERR) {
            if(!getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)&sockerr, &errlen))
                debug(DBG_WARN, "SSL Accept failed: %s", strerror(sockerr));
            else
                debug(DBG_WARN, "SSL Accept failed: unknown error");
        } else if (fds[0].revents & POLLHUP) {
                debug(DBG_WARN, "SSL Accept error: hang up");
        } else if (fds[0].revents & POLLNVAL) {
                debug(DBG_WARN, "SSL Accept error: fd not open");
        } else {
            r = SSL_accept(ssl);
            if (r <= 0) {
                switch (SSL_get_error(ssl, r)) {
                    case SSL_ERROR_WANT_WRITE:
                        want_write = 1;
                    case SSL_ERROR_WANT_READ:
                        continue;
                }
            }
        }
        break;
    }

    if (fcntl(socket, F_SETFL, origflags) == -1)
        debugerrno(errno, DBG_WARN, "Failed to set original flags back");
    return r;
}

int sslconnecttimeout(SSL *ssl, int timeout) {
    int socket, origflags, ndesc, r = -1, sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    struct pollfd fds[1];
    uint8_t want_write = 1;

    socket = SSL_get_fd(ssl);
    origflags = fcntl(socket, F_GETFL, 0);
    if (origflags == -1) {
        debugerrno(errno, DBG_WARN, "Failed to get flags");
        return -1;
    }
    if (fcntl(socket, F_SETFL, origflags | O_NONBLOCK) == -1) {
        debugerrno(errno, DBG_WARN, "Failed to set O_NONBLOCK");
        return -1;
    }

    while (r < 1) {
        fds[0].fd = socket;
        fds[0].events = POLLIN;
        if (want_write) {
            fds[0].events |= POLLOUT;
            want_write = 0;
        }
        if ((ndesc = poll(fds, 1, timeout * 1000)) < 1) {
            if (ndesc == 0)
                debug(DBG_DBG, "sslconnecttimeout: timeout during SSL_connect");
            else
                debugerrno(errno, DBG_DBG, "sslconnecttimeout: poll error");
            break;
        }

        if (fds[0].revents & POLLERR) {
            if(!getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)&sockerr, &errlen))
                debug(DBG_WARN, "SSL Connection failed: %s", strerror(sockerr));
            else
                debug(DBG_WARN, "SSL Connection failed: unknown error");
        } else if (fds[0].revents & POLLHUP) {
                debug(DBG_WARN, "SSL Connect error: hang up");
        } else if (fds[0].revents & POLLNVAL) {
                debug(DBG_WARN, "SSL Connect error: fd not open");
        } else {
            r = SSL_connect(ssl);
            if (r <= 0) {
                switch (SSL_get_error(ssl, r)) {
                    case SSL_ERROR_WANT_WRITE:
                        want_write = 1;
                    case SSL_ERROR_WANT_READ:
                        continue;
                }
            }
        }
        break;
    }

    if (fcntl(socket, F_SETFL, origflags) == -1)
        debugerrno(errno, DBG_WARN, "Failed to set original flags back");
    return r;
}

#else
/* Just to makes file non-empty, should rather avoid compiling this file when not needed */
static void tlsdummy() {
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
