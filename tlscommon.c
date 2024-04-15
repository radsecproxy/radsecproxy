/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2011,2015-2016, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
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
#include <sys/stat.h>
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
#include <assert.h>
#include "debug.h"
#include "hash.h"
#include "util.h"
#include "hostport.h"
#include "radsecproxy.h"

static struct hash *tlsconfs = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10101000
static struct tls *tlsdefaultpsk = NULL;
#endif

#define COOKIE_SECRET_LENGTH 16
static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
static uint8_t cookie_secret_initialized = 0;

int RSP_EX_DATA_CONFIG;
int RSP_EX_DATA_CONFIG_LIST;

struct certattrmatch {
    int (*matchfn)(GENERAL_NAME *, struct certattrmatch *);
    int type;
    char * exact;
    regex_t *regex;
    ASN1_OBJECT *oid;
    struct in6_addr ipaddr;
    int af;
    char * debugname;
};

/* callbacks for making OpenSSL < 1.1 thread safe */
#if OPENSSL_VERSION_NUMBER < 0x10100000
static pthread_mutex_t *ssl_locks = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10000000
unsigned long ssl_thread_id() {
    return (unsigned long)pthread_self();
}
#else
void ssl_thread_id(CRYPTO_THREADID *id) {
    CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}
#endif


void ssl_locking_callback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
       pthread_mutex_lock(&ssl_locks[type]);
    else
       pthread_mutex_unlock(&ssl_locks[type]);
}
#endif

void sslinit(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
    int i;

    SSL_library_init();

    ssl_locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (!ssl_locks)
        debugx(1, DBG_ERR, "malloc failed");

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&ssl_locks[i], NULL);
    }
#if OPENSSL_VERSION_NUMBER < 0x10000000
    CRYPTO_set_id_callback(ssl_thread_id);
#else
    CRYPTO_THREADID_set_callback(ssl_thread_id);
#endif
    CRYPTO_set_locking_callback(ssl_locking_callback);
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(0, NULL);
    RSP_EX_DATA_CONFIG = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0, NULL, NULL, NULL, NULL);
    RSP_EX_DATA_CONFIG_LIST = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0, NULL, NULL, NULL, NULL);
#endif
}

/**
 * Print a human readable form of X509_NAME
 * 
 * This is a direct replacement for X509_NAME_oneline() which should no longer be used.
 * 
 * @param name The X509_Name to be printed.
 */
static char *print_x509_name(X509_NAME *name) {
    BIO *bio;
    char *buf;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        debug(DBG_ERR, "getcertsubject: BIO_new failed");
        return NULL;
    }

    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);

    buf = malloc(BIO_number_written(bio)+1);
    if (buf) {
        BIO_read(bio, buf, BIO_number_written(bio));
        buf[BIO_number_written(bio)] = '\0';
    } else {
        debug(DBG_ERR, "getcertsubject: malloc failed");
    }
    BIO_free(bio);

    return buf;
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
            buf = print_x509_name(X509_get_subject_name(err_cert));
        debug(DBG_WARN, "verify error: num=%d:%s:depth=%d:%s", err, X509_verify_cert_error_string(err), depth, buf ? buf : "");
        free(buf);
        buf = NULL;

        switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            if (err_cert) {
            buf = print_x509_name(X509_get_issuer_name(err_cert));
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
    uint8_t result[EVP_MAX_MD_SIZE] = {0};
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
    uint8_t result[EVP_MAX_MD_SIZE] = {0};
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

#if OPENSSL_VERSION_NUMBER >= 0x10101000
int psk_use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id, size_t *idlen, SSL_SESSION **sess) {
    struct clsrvconf *conf = NULL;
    STACK_OF(SSL_CIPHER) *ciphers;
    const SSL_CIPHER *cipher;

    conf = (struct clsrvconf *) SSL_get_ex_data(ssl, RSP_EX_DATA_CONFIG);
    if (!conf || !conf->pskid || !conf->pskkey) {
        debug(DBG_DBG, "psk_use_session_cb: no PSK data configured for tls connection");
        *sess = NULL;
        return 1;
    }

    debug(DBG_DBG, "psk_use_session_cb: using PSK id %s, key length %d", conf->pskid, conf->pskkeylen);

    *sess = SSL_SESSION_new();
    if (! *sess) {
        debug(DBG_ERR, "psk_use_session_cb: failed to create new SSL session");
        return 0;
    }

    *id = (unsigned char *) conf->pskid;
    *idlen = strlen(conf->pskid);
    if (!SSL_SESSION_set1_master_key(*sess, (unsigned char *) conf->pskkey, conf->pskkeylen)) {
        debug(DBG_ERR, "psk_use_session_cb: failed to set PSK key");
        return 0;
    }

    if (!SSL_SESSION_set_protocol_version(*sess, TLS1_3_VERSION)) {
        debug(DBG_ERR, "psk_use_session_cb: failed to set tls version 1.3, mandatory for PSK!");
        return 0;
    }

    ciphers = SSL_get1_supported_ciphers(ssl);
    if (!ciphers) {
        debug(DBG_ERR, "psk_use_session_cb: failed to get supported ciphers");
        return 0;
    }
    cipher = sk_SSL_CIPHER_value(ciphers,0);
    sk_SSL_CIPHER_free(ciphers);
    if (!cipher) {
        debug(DBG_ERR, "psk_use_session_cb: first supported cipher is null!");
        return 0;
    }
    debug(DBG_DBG, "psk_use_session_db: setting session cipher %s", SSL_CIPHER_get_name(cipher));
    if (!SSL_SESSION_set_cipher(*sess, cipher)) {
        debug(DBG_ERR, "psk_use_session_db: failed to set session cipher");
        return 0;
    }

    /*disable certificate verification since we don't expect one for PSK*/
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

    return 1;
}

int psk_find_session_cb(SSL *ssl, const unsigned char *id, size_t idlen, SSL_SESSION **sess) {
    struct clsrvconf *conf = NULL;
    struct list* candidates = NULL;
    struct list_node *node = NULL;
    const SSL_CIPHER *cipher;

    candidates = (struct list *) SSL_get_ex_data(ssl, RSP_EX_DATA_CONFIG_LIST);
    if (!candidates) {
        debug(DBG_DBG, "psk_find_session_cb: no candidate list found in ssl object");
        *sess = NULL;
        return 1;
    }
    for(node = list_first(candidates); node; node = list_next(node)) {
        struct clsrvconf *candidate = (struct clsrvconf *)node->data;
        if (candidate->pskid && strcmp((const char *)id, candidate->pskid) == 0) {
            conf = candidate;
            break;
        }
    }
    if (!conf) {
        debug(DBG_DBG, "psk_find_session_cb: no client with PSK id %s found", id);
        *sess = NULL;
        return 1;
    }

    debug(DBG_DBG, "psk_find_session_cb: PSK id %s matches client %s, key length %d", conf->pskid, conf->name, conf->pskkeylen);
    if (!SSL_set_ex_data(ssl, RSP_EX_DATA_CONFIG, conf)) {
        debug(DBG_ERR, "psk_find_session_cb: failed to set ssl ex data");
        return 0;
    }

     *sess = SSL_SESSION_new();
    if (! *sess) {
        debug(DBG_ERR, "psk_find_session_cb: failed to create new SSL session");
        return 0;
    }
    if (!SSL_SESSION_set1_master_key(*sess, (unsigned char *) conf->pskkey, conf->pskkeylen)) {
        debug(DBG_ERR, "psk_find_session_cb: failed to set PSK key");
        return 0;
    }

    if (!SSL_SESSION_set_protocol_version(*sess, TLS1_3_VERSION)) {
        debug(DBG_ERR, "psk_find_session_cb: failed to set tls version 1.3, mandatory for PSK!");
        return 0;
    }

    cipher = SSL_get_pending_cipher(ssl);
    if (!cipher) {
         debug(DBG_ERR, "psk_find_session_cb: failed to get pending cipher");
         return 0;
    }
    debug(DBG_DBG, "psk_find_session_cb: setting session cipher %s", SSL_CIPHER_get_name(cipher));
    if (!SSL_SESSION_set_cipher(*sess, cipher)) {
        debug(DBG_ERR, "psk_find_session_cb: failed t set session cipher");
        return 0;
    }

    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

    return 1;
}

void keylog_cb (const SSL *ssl, const char *line) {
    static FILE *keylog = NULL;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static int keyloginitialized = 0;

    pthread_mutex_lock(&mutex);
    if (!keyloginitialized) {
        mode_t oldumask = umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if ( !(keylog = fopen(getenv(RSP_KEYLOG_ENV), "a")) )
            debugerrno(errno, DBG_ERR, "keylog_cb: error opening file %s", getenv(RSP_KEYLOG_ENV));
        else
            setlinebuf(keylog);
        umask(oldumask);
        keyloginitialized = 1;
    }

    if (keylog)
        if (fputs(line, keylog) == EOF ||
            fputc('\n', keylog) == EOF) {

            debugerrno(errno, DBG_ERR, "kehlog_cb: error writing to file %s", getenv(RSP_KEYLOG_ENV));
            fclose(keylog);
            keylog = NULL;
            keyloginitialized = 0;
        }
    pthread_mutex_unlock(&mutex);
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

    if (!conf->cacertfile && !conf->cacertpath) {
        debug(DBG_DBG, "tlsaddcacrl: No cacertifle or cacertpath specified for TLS %s, skip adding CAs", conf->name);
        return 1;
    }

    x509_s = X509_STORE_new();
    if (!X509_STORE_load_locations(x509_s, conf->cacertfile, conf->cacertpath)) {
        while ((error = ERR_get_error()))
            debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
        debug(DBG_ERR, "tlsaddcacrl: Error loading CAs and CRLs in TLS context %s", conf->name);

        X509_STORE_free(x509_s);
        return 0;
    }
    if (conf->crlcheck)
        X509_STORE_set_flags(x509_s, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    if (conf->vpm)
        X509_STORE_set1_param(x509_s, conf->vpm);
    SSL_CTX_set_cert_store(ctx, x509_s);

    calist = sk_X509_NAME_new_null();
    if (conf->cacertfile) {
        debug(DBG_DBG, "tlsaddcacrl: loading subject names from file %s", conf->cacertfile);
        if (!SSL_add_file_cert_subjects_to_stack(calist, conf->certfile)) {
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
            debug(DBG_ERR, "tlsaddcacrl: failed to load CA subject names from file %s", conf->cacertfile);
        }
    }
    if (conf->cacertpath) {
        debug(DBG_DBG, "tlsaddcacrl: loading subject names from path %s", conf->cacertpath);
        if (!SSL_add_dir_cert_subjects_to_stack(calist, conf->cacertpath)) {
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
            debug(DBG_ERR, "tlsaddcacrl: failed to load CA subject names from path %s", conf->cacertpath);
        }
    }
    ERR_clear_error(); /* add_dir_cert_subj returns errors on success */
    SSL_CTX_set_client_CA_list(ctx, calist);

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
        if (ctx != NULL) {
            if (conf->tlsminversion >= 0)
                SSL_CTX_set_min_proto_version(ctx, conf->tlsminversion);
            if (conf->tlsmaxversion >= 0)
                SSL_CTX_set_max_proto_version(ctx, conf->tlsmaxversion);
        }
#else
        /* No TLS_method(), use SSLv23_method() and disable SSLv2 and SSLv3. */
        ctx = SSL_CTX_new(SSLv23_method());
        if (ctx != NULL) {
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        }
#endif
#ifdef DEBUG
        if (ctx != NULL) {
            SSL_CTX_set_info_callback(ctx, ssl_info_callback);
        }
#endif
        break;
#endif
#ifdef RADPROT_DTLS
    case RAD_DTLS:
#if OPENSSL_VERSION_NUMBER >= 0x10002000
        /* DTLS_method() seems to have been introduced in OpenSSL 1.0.2. */
        ctx = SSL_CTX_new(DTLS_method());
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        if (ctx != NULL) {
            if (conf->dtlsminversion >= 0)
                SSL_CTX_set_min_proto_version(ctx, conf->dtlsminversion);
            if (conf->dtlsmaxversion >= 0)
                SSL_CTX_set_max_proto_version(ctx, conf->dtlsmaxversion);
        }
#endif
#else
        ctx = SSL_CTX_new(DTLSv1_method());
#endif
#ifdef DEBUG
        if (ctx != NULL) {
            SSL_CTX_set_info_callback(ctx, ssl_info_callback);
        }
#endif
        if (ctx != NULL) {
            SSL_CTX_set_read_ahead(ctx, 1);
        }
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
    if (conf->certfile) {
        if (!SSL_CTX_use_certificate_chain_file(ctx, conf->certfile) ||
            !SSL_CTX_use_PrivateKey_file(ctx, conf->certkeyfile, SSL_FILETYPE_PEM) ||
            !SSL_CTX_check_private_key(ctx)) {
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
            debug(DBG_ERR, "tlsloadclientcert: Error loading certificate and/or key in TLS context %s", conf->name);
            ERR_clear_error();
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        debug(DBG_DBG, "tlsloadclientcert: no certificate specified, TLS %s can only be used for TLS-PSK", conf->name);
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

    if (conf->cipherlist) {
        if (!SSL_CTX_set_cipher_list(ctx, conf->cipherlist)) {
            debug(DBG_ERR, "tlscreatectx: Failed to set cipher list in TLS context %s", conf->name);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000
    if (conf->ciphersuites) {
        if (!SSL_CTX_set_ciphersuites(ctx, conf->ciphersuites)) {
            debug(DBG_ERR, "tlscreatectx: Failed to set ciphersuites in TLS context %s", conf->name);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
#endif

    if (conf->dhparam) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        if (!SSL_CTX_set0_tmp_dh_pkey(ctx, conf->dhparam)) {
#else
        if (!SSL_CTX_set_tmp_dh(ctx, conf->dhparam)) {
#endif
            while ((error = ERR_get_error()))
                debug(DBG_WARN, "tlscreatectx: SSL: %s", ERR_error_string(error, NULL));
            debug(DBG_WARN, "tlscreatectx: Failed to set dh params. Can continue, but some ciphers might not be available.");
        }
    }
#if OPENSSL_VERSION_NUMBER >= 0x10101000
    else {
        if (!SSL_CTX_set_dh_auto(ctx, 1)) {
            while ((error = ERR_get_error()))
                debug(DBG_WARN, "tlscreatectx: SSL: %s", ERR_error_string(error, NULL));
            debug(DBG_WARN, "tlscreatectx: Failed to set automatic dh params. Can continue, but some ciphers might not be available.");
        }
    }
#endif

    SSL_CTX_set_cookie_generate_cb(ctx, cookie_generate_cb);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify_cb);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
    SSL_CTX_set_verify_depth(ctx, MAX_CERT_DEPTH + 1);
#if OPENSSL_VERSION_NUMBER >= 0x10101000
    SSL_CTX_set_psk_use_session_callback(ctx, psk_use_session_cb);
    SSL_CTX_set_psk_find_session_callback(ctx, psk_find_session_cb);
    SSL_CTX_set_options(ctx, SSL_CTX_get_options(ctx) & ~SSL_OP_ALLOW_NO_DHE_KEX);

    if (getenv(RSP_KEYLOG_ENV))
        SSL_CTX_set_keylog_callback(ctx, keylog_cb);
#endif

    debug(DBG_DBG, "tlscreatectx: created TLS context %s", conf->name);
    return ctx;
}

struct tls *tlsgettls(char *alt1, char *alt2) {
    struct tls *t;

    t = hash_read(tlsconfs, alt1, strlen(alt1));
    if (!t && alt2)
	t = hash_read(tlsconfs, alt2, strlen(alt2));
    return t;
}

struct tls *tlsgetdefaultpsk(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000
    if (!tlsdefaultpsk) {
        if (!(tlsdefaultpsk = calloc(1, sizeof(struct tls)))) {
            debug(DBG_ERR, "malloc failed");
            return NULL;
        }

        tlsdefaultpsk->name = "_psk_default";
        tlsdefaultpsk->ciphersuites = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        tlsdefaultpsk->tlsminversion = TLS1_3_VERSION;
    }
    return tlsdefaultpsk;
#else
    debugx(1,DBG_ERR, "tlsgetdefaultpsk: use of TLS1.3-PSK requires openssl >= 1.1.1");
    return NULL;
#endif
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
            if (t->tlsexpiry <= now.tv_sec) {
                t->tlsexpiry = now.tv_sec + t->cacheexpiry;
                if (!tlsaddcacrl(t->tlsctx, t))
                    debug(DBG_WARN, "tlsgetctx: cache reload for TLS context %s failed, continue with old state!",t->name);
            }
        }
        if (!t->tlsctx) {
            t->tlsctx = tlscreatectx(RAD_TLS, t);
            if (t->cacheexpiry >= 0)
                t->tlsexpiry = now.tv_sec + t->cacheexpiry;
        }
        return t->tlsctx;
#endif
#ifdef RADPROT_DTLS
    case RAD_DTLS:
        if (t->dtlsexpiry && t->dtlsctx) {
            if (t->dtlsexpiry <= now.tv_sec) {
                t->dtlsexpiry = now.tv_sec + t->cacheexpiry;
                if (!tlsaddcacrl(t->dtlsctx, t))
                    debug(DBG_WARN, "tlsgetctx: cache reload for DTLS context %s failed, continue with old state!",t->name);
            }
        }
        if (!t->dtlsctx) {
            t->dtlsctx = tlscreatectx(RAD_DTLS, t);
            if (t->cacheexpiry >= 0)
                t->dtlsexpiry = now.tv_sec + t->cacheexpiry;
        }
        return t->dtlsctx;
#endif
    }
    return NULL;
}

void tlsreload(void) {
    struct tls *conf;
    struct hash_entry *entry;
    struct timeval now;
    SSL_CTX *newctx;

    debug (DBG_NOTICE, "reloading certs, CAs, CRLs");

    gettimeofday(&now, NULL);

    for (entry = hash_first(tlsconfs); entry; entry = hash_next(entry)) {
        conf = (struct tls *)entry->data;
#ifdef RADPROT_TLS
        if (conf->tlsctx) {
            pthread_mutex_lock(&conf->lock);
            if (conf->tlsexpiry)
                conf->tlsexpiry = now.tv_sec + conf->cacheexpiry;
            newctx = tlscreatectx(RAD_TLS, conf);
            if (!newctx) {
                debug(DBG_ERR, "tlsreload: failed to create new TLS context for %s, context is NOT updated!", conf->name);
            } else {
                SSL_CTX_free(conf->tlsctx);
                conf->tlsctx = newctx;
            }
            pthread_mutex_unlock(&conf->lock);
        }
#endif
#ifdef RADPROT_DTLS
        if (conf->dtlsctx) {
            pthread_mutex_lock(&conf->lock);
            if (conf->dtlsexpiry)
                conf->dtlsexpiry = now.tv_sec + conf->cacheexpiry;
            newctx = tlscreatectx(RAD_DTLS, conf);
            if (!newctx) {
                debug(DBG_ERR, "tlsreload: failed to create new DTLS context for %s, context is NOT updated!", conf->name);
            } else {
                SSL_CTX_free(conf->dtlsctx);
                conf->dtlsctx = newctx;
            }
            pthread_mutex_unlock(&conf->lock);
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

static int certattr_matchrid(GENERAL_NAME *gn, struct certattrmatch *match) {
    return OBJ_cmp(gn->d.registeredID, match->oid) == 0 ? 1 : 0;
}

static int certattr_matchip(GENERAL_NAME *gn, struct certattrmatch *match){
    int l = ASN1_STRING_length(gn->d.iPAddress);
    return (((match->af == AF_INET && l == sizeof(struct in_addr)) || (match->af == AF_INET6 && l == sizeof(struct in6_addr)))
        && !memcmp(ASN1_STRING_get0_data(gn->d.iPAddress), &match->ipaddr, l)) ? 1 : 0 ;
}

static int _general_name_regex_match(char *v, int l, struct certattrmatch *match) {
    char *s;
    if (l <= 0 ) 
        return 0;
    if (match->exact) {
        if (l == strlen(match->exact) && memcmp(v, match->exact, l) == 0)
            return 1;
        return 0;
    }

    s = stringcopy((char *)v, l);
    if (!s) {
        debug(DBG_ERR, "malloc failed");
        return 0;
    }
    debug(DBG_DBG, "matchtregex: matching %s", s);
    if (regexec(match->regex, s, 0, NULL, 0) == 0) {
        free(s);
        return 1;
    }
    free(s);
    return 0;
}

static int certattr_matchregex(GENERAL_NAME *gn, struct certattrmatch *match) {
    return _general_name_regex_match((char *)ASN1_STRING_get0_data(gn->d.ia5), ASN1_STRING_length(gn->d.ia5), match);
}

static int certattr_matchothername(GENERAL_NAME *gn, struct certattrmatch *match) {
    if (OBJ_cmp(gn->d.otherName->type_id, match->oid) != 0)
        return 0;
    return _general_name_regex_match((char *)ASN1_STRING_get0_data(gn->d.otherName->value->value.octet_string),
                                     ASN1_STRING_length(gn->d.otherName->value->value.octet_string),
                                     match);
    
}

static int certattr_matchcn(X509 *cert, struct certattrmatch *match){
    int loc;
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
        if (_general_name_regex_match((char *) ASN1_STRING_get0_data(t), ASN1_STRING_length(t), match))
            return 1;
    }
    return 0;
}

/* returns
   1 if expected type is present and matches
   0 if expected type is not present
   -1 if expected type is present but does not match */
static int matchsubjaltname(X509 *cert, struct certattrmatch* match) {
    GENERAL_NAME *gn;
    int loc, n,i,r = 0;
    char *fail = NULL, *tmp, *s;
    STACK_OF(GENERAL_NAME) *alt;

    /*special case: don't search in SAN, but CN field in subject */
    if (match->type == -1)
        return certattr_matchcn(cert, match);

    loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (loc < 0) 
        return 0;

    alt = X509V3_EXT_d2i(X509_get_ext(cert, loc));
    if (!alt)
        return 0;

    n = sk_GENERAL_NAME_num(alt);
    for (i = 0; i < n; i++) {
        gn = sk_GENERAL_NAME_value(alt, i);
        if (gn->type == match->type) {
            r = match->matchfn(gn, match);
            if (r)
                break;
            r = -1;
        }
        /*legacy print non-matching SAN*/
        if (gn->type == GEN_DNS || gn->type == GEN_URI) {
            s = stringcopy((char *)ASN1_STRING_get0_data(gn->d.ia5), ASN1_STRING_length(gn->d.ia5));
            if (!s) continue;
            tmp = fail;
            if (asprintf(&fail, "%s%s%s", tmp ? tmp : "", tmp ? ", " : "", s) >= 0)
                free(tmp);
            else
                fail = tmp;
            free(s);
        }
    }

    if (r<1)
        debug(DBG_DBG, "matchsubjaltname: no matching Subject Alt Name found! (%s)", fail);
    free(fail);

    GENERAL_NAMES_free(alt);
    return r;
}

int certnamecheck(X509 *cert, struct hostportres *hp) {
    int r = 0;
    struct certattrmatch match;

    memset(&match, 0, sizeof(struct certattrmatch));

    r = 0;
    if (hp->prefixlen != 255) {
        /* we disable the check for prefixes */
        return 1;
    }
    if (inet_pton(AF_INET, hp->host, &match.ipaddr))
        match.af = AF_INET;
    else if (inet_pton(AF_INET6, hp->host, &match.ipaddr))
        match.af = AF_INET6;
    else
        match.af = 0;
    match.exact = hp->host;

    if (match.af) {
        match.matchfn = &certattr_matchip;
        match.type = GEN_IPADD;
        r = matchsubjaltname(cert, &match);
    }
    if (!r) {
        match.matchfn = &certattr_matchregex;
        match.type = GEN_DNS;
        r = matchsubjaltname(cert, &match);
    }
    if (r) {
        if (r > 0) {
            debug(DBG_DBG, "certnamecheck: Found subjectaltname matching %s %s", match.af ? "address" : "host", hp->host);
            return 1;
        }
        debug(DBG_WARN, "certnamecheck: No subjectaltname matching %s %s", match.af ? "address" : "host", hp->host);
    } else { /* as per RFC 6125 6.4.4: CN MUST NOT be matched if SAN is present */
        if (certattr_matchcn(cert, &match)) {
            debug(DBG_DBG, "certnamecheck: Found cn matching host %s", hp->host);
            return 1;
        }
        debug(DBG_WARN, "certnamecheck: cn not matching host %s", hp->host);
    }
    return 0;
}

int certnamecheckany(X509 *cert, struct list *hostports) {
    struct list_node *entry;
    for (entry = list_first(hostports); entry; entry = list_next(entry)) {
        if (certnamecheck(cert, (struct hostportres *)entry->data)) return 1;
    }
    return 0;
}

int verifyconfcert(X509 *cert, struct clsrvconf *conf, struct hostportres *hpconnected) {
    char *subject;
    int ok = 1;
    struct list_node *entry;

    subject = getcertsubject(cert);
    debug(DBG_DBG, "verifyconfcert: verify certificate for host %s, subject %s", conf->name, subject);
    if (conf->certnamecheck) {
        debug(DBG_DBG, "verifyconfcert: verify hostname");
        if (conf->servername) {
            struct hostportres servername = {.host = conf->servername, .port = NULL, .prefixlen = 255, .addrinfo = NULL};
            if (!certnamecheck(cert, &servername)){
                debug(DBG_WARN, "verifyconfcert: certificate name check failed for host %s (%s)", conf->name, servername.host);
                ok = 0;
            }
        }
        else if (hpconnected) {
            if (!certnamecheck(cert, hpconnected)) {
                debug(DBG_WARN, "verifyconfcert: certificate name check failed for host %s (%s)", conf->name, hpconnected->host);
                ok = 0;
            }
        } else {
            if (!certnamecheckany(cert, conf->hostports)) {
                debug(DBG_DBG, "verifyconfcert: no matching CN or SAN found for host %s", conf->name);
                ok = 0;
            }
        }
    }

    for (entry = list_first(conf->matchcertattrs); entry; entry = list_next(entry)) {
        if (matchsubjaltname(cert, (struct certattrmatch *)entry->data) < 1) {
            debug(DBG_WARN, "verifyconfcert: %s not matching for host %s (%s)", ((struct certattrmatch *)entry->data)->debugname, conf->name, subject);
            ok = 0;
        } else {
            debug(DBG_DBG, "verifyconfcert: %s matching for host %s (%s)", ((struct certattrmatch *)entry->data)->debugname, conf->name, subject);
        }
    }

    free(subject);
    return ok;
}

char *getcertsubject(X509 *cert) {
    if (!cert) return NULL;
    return print_x509_name(X509_get_subject_name(cert));
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
static int parse_tls_version(const char* version) {
    if (!strcasecmp("SSL3", version)) {
        return SSL3_VERSION;
    } else if (!strcasecmp("TLS1", version)) {
        return TLS1_VERSION;
    } else if (!strcasecmp("TLS1_1", version)) {
        return TLS1_1_VERSION;
    } else if (!strcasecmp("TLS1_2", version)) {
        return TLS1_2_VERSION;
#if OPENSSL_VERSION_NUMBER >= 0x10101000
    } else if (!strcasecmp("TLS1_3", version)) {
        return TLS1_3_VERSION;
#endif
    } else if (!strcasecmp("DTLS1", version)) {
        return DTLS1_VERSION;
    } else if (!strcasecmp("DTLS1_2", version)) {
        return DTLS1_2_VERSION;
    } else if (!strcasecmp("", version)) {
        return 0;
    } else {
        return -1;
    }
}

static int conf_tls_version(const char *version, int *min, int *max) {
    char *ver, *s, *smin, *smax;
    ver = stringcopy(version, strlen(version));
    s = strchr(ver, ':');
    if (!s) {
        smin = smax = ver;
    } else {
        *s =  '\0';
        smin = ver;
        smax = s+1;
    }
    *min = parse_tls_version(smin);
    *max = parse_tls_version(smax);
    free(ver);
    return *min >=0 && *max >=0 && (*max == 0 || *min <= *max);
}
#endif

int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    struct tls *conf;
    char *tlsversion = NULL;
    char *dtlsversion = NULL;
    char *dhfile = NULL;
    unsigned long error;

    debug(DBG_DBG, "conftls_cb called for %s", block);

    conf = calloc(1, sizeof(struct tls));
    if (!conf) {
        debug(DBG_ERR, "conftls_cb: malloc failed");
        return 0;
    }
    conf->cacheexpiry = -1;

    if (!getgenericconfig(cf, block,
        "CACertificateFile", CONF_STR, &conf->cacertfile,
        "CACertificatePath", CONF_STR, &conf->cacertpath,
        "CertificateFile", CONF_STR, &conf->certfile,
        "CertificateKeyFile", CONF_STR, &conf->certkeyfile,
        "CertificateKeyPassword", CONF_STR, &conf->certkeypwd,
        "CacheExpiry", CONF_LINT, &conf->cacheexpiry,
        "CRLCheck", CONF_BLN, &conf->crlcheck,
        "PolicyOID", CONF_MSTR, &conf->policyoids,
        "CipherList", CONF_STR, &conf->cipherlist,
        "CipherSuites", CONF_STR, &conf->ciphersuites,
        "TlsVersion", CONF_STR, &tlsversion,
        "DtlsVersion", CONF_STR, &dtlsversion,
        "DhFile", CONF_STR, &dhfile,
        NULL
    )) {
        debug(DBG_ERR, "conftls_cb: configuration error in block %s", val);
        goto errexit;
    }
    if (!conf->certfile) {
        debug(DBG_DBG, "conftls_db: tls %s has no certificate specified, can only be used for PSK", val);
    } else {
        if (!conf->certkeyfile) {
            debug(DBG_ERR, "conftls_cb: TLSCertificateKeyFile must be specified together with TLSCertificateFile in block %s", val);
            goto errexit;
        }
        if (!conf->cacertfile && !conf->cacertpath) {
            debug(DBG_ERR, "conftls_cb: CA Certificate file or path need to be specified together with TLSCertificateFile in block %s", val);
            goto errexit;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    /* use -1 as 'not set' value */
    conf->tlsminversion = conf->tlsmaxversion = conf->dtlsminversion = conf->dtlsmaxversion = -1;
    if (tlsversion) {
        if(!conf_tls_version(tlsversion, &conf->tlsminversion, &conf->tlsmaxversion)) {
            debug(DBG_ERR, "error in block %s, invalid TlsVersion %s", val, tlsversion);
            goto errexit;
        }
        free (tlsversion);
        tlsversion = NULL;
    }
    if (dtlsversion) {
        if(!conf_tls_version(dtlsversion, &conf->dtlsminversion, &conf->dtlsmaxversion)) {
            debug(DBG_ERR, "error in block %s, invalid DtlsVersion %s", val, dtlsversion);
            goto errexit;
        }
        free (dtlsversion);
        dtlsversion = NULL;
    }
#else
    if (tlsversion || dtlsversion) {
        debug(DBG_ERR, "error in block %s, setting tls/dtls version requires openssl 1.1.0 or later", val);
        goto errexit;
    }
#endif

    if (dhfile) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        BIO *bio = BIO_new_file(dhfile, "r");
        if (bio) {
            conf->dhparam = EVP_PKEY_new();
            if (!PEM_read_bio_Parameters(bio, &conf->dhparam)) {
                BIO_free(bio);
                while ((error = ERR_get_error()))
                    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
                debug(DBG_ERR, "error in block %s: Failed to load DhFile %s.", val, dhfile);
                goto errexit;
            }
            BIO_free(bio);
        }
#else
        FILE *dhfp = fopen(dhfile, "r");
        if (dhfp) {
            conf->dhparam = PEM_read_DHparams(dhfp, NULL, NULL, NULL);
            fclose(dhfp);
            if (!conf->dhparam) {
                while ((error = ERR_get_error()))
                    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
                debug(DBG_ERR, "error in block %s: Failed to load DhFile %s.", val, dhfile);
                goto errexit;
            }
        } else {
            debug(DBG_ERR, "error in block %s, DhFile: can't open file %s", val, dhfile);
            goto errexit;
        }
        free(dhfile);
        dhfile = NULL;
#endif
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
    debug(DBG_DBG, "conftls_cb: added TLS block %s", val);
    return 1;

errexit:
    free(conf->cacertfile);
    free(conf->cacertpath);
    free(conf->certfile);
    free(conf->certkeyfile);
    free(conf->certkeypwd);
    freegconfmstr(conf->policyoids);
    free(tlsversion);
    free(dtlsversion);
    free(dhfile);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_PKEY_free(conf->dhparam);
#else
    DH_free(conf->dhparam);
#endif
    free(conf);
    return 0;
}

static regex_t *compileregex(char *regstr) {
    regex_t *result;
    if (regstr[0] != '/')
        return NULL;
    regstr++;

    if (regstr[strlen(regstr) - 1] == '/')
        regstr[strlen(regstr) - 1] = '\0';
    if (!*regstr)
        return NULL;

    result = malloc(sizeof(regex_t));
    if (!result) {
        debug(DBG_ERR, "malloc failed");
        return NULL;
    }
    if (regcomp(result, regstr, REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
        free(result);
        debug(DBG_ERR, "failed to compile regular expression %s", regstr);
        return NULL;
    }
    return result;
}

int addmatchcertattr(struct clsrvconf *conf, const char *match) {
    struct certattrmatch *certattrmatch;
    char *pos, *colon, *matchcopy;
    
    if (!conf->matchcertattrs) {
        conf->matchcertattrs = list_create();
    }

    certattrmatch = malloc(sizeof(struct certattrmatch));
    if (!certattrmatch) return 0;
    memset(certattrmatch, 0, sizeof(struct certattrmatch));

    matchcopy = stringcopy(match,0);
    pos = matchcopy;
    colon = strchr(pos, ':');
    if (!colon) goto errexit;

    if (strncasecmp(pos, "CN", colon - pos) == 0) {
        if(!(certattrmatch->regex = compileregex(colon+1))) goto errexit;
        certattrmatch->type = -1;
        certattrmatch->matchfn = NULL; /*special case: don't search in SAN, but CN field in subject */
    } 
    else if (strncasecmp(pos, "SubjectAltName", colon - pos) == 0) {
        pos = colon+1;
        colon = strchr(pos, ':');
        if (!colon) goto errexit;

        if (strncasecmp(pos, "IP", colon - pos) == 0) {
            pos = colon+1;
            if (inet_pton(AF_INET, pos, &certattrmatch->ipaddr))
                certattrmatch->af = AF_INET;
            else if (inet_pton(AF_INET6, pos, &certattrmatch->ipaddr))
                certattrmatch->af = AF_INET6;
            else
                goto errexit;
            certattrmatch->type = GEN_IPADD;
            certattrmatch->matchfn = &certattr_matchip;
        }
        else if(strncasecmp(pos, "URI", colon - pos) == 0) {
            if(!(certattrmatch->regex = compileregex(colon+1))) goto errexit;
            certattrmatch->type = GEN_URI;
            certattrmatch->matchfn = &certattr_matchregex;
        }
        else if(strncasecmp(pos, "DNS", colon - pos) == 0) {
            if(!(certattrmatch->regex = compileregex(colon+1))) goto errexit;
            certattrmatch->type = GEN_DNS;
            certattrmatch->matchfn = &certattr_matchregex;
        }
        else if(strncasecmp(pos, "rID", colon - pos) == 0) {
            certattrmatch->oid = OBJ_txt2obj(colon+1, 0);
            if (!certattrmatch->oid) goto errexit;
            certattrmatch->type = GEN_RID;
            certattrmatch->matchfn = &certattr_matchrid;
        }
        else if(strncasecmp(pos, "otherNAme", colon - pos) == 0){
            pos = colon+1;
            colon = strchr(pos, ':');
            if(!colon) goto errexit;
            *colon = '\0';
            if(!(certattrmatch->oid = OBJ_txt2obj(pos,0))) goto errexit;
            if(!(certattrmatch->regex = compileregex(colon+1))) goto errexit;
            certattrmatch->type = GEN_OTHERNAME;
            certattrmatch->matchfn = &certattr_matchothername;
        }
        else goto errexit;
    } 
    else goto errexit;

    certattrmatch->debugname = stringcopy(match, 0);
    if(!list_push(conf->matchcertattrs, certattrmatch)) goto errexit;
    free(matchcopy);
    return 1;

errexit:
    free(certattrmatch);
    free(matchcopy);
    return 0;
}

void freematchcertattr(struct clsrvconf *conf) {
    struct list_node *entry;
    struct certattrmatch *match;

    if (conf->matchcertattrs) {
        for (entry = list_first(conf->matchcertattrs); entry; entry=list_next(entry)) {
            match = ((struct certattrmatch*)entry->data);
            free(match->debugname);
            free(match->exact);
            ASN1_OBJECT_free(match->oid);
            if(match->regex)
                regfree(match->regex);
            free(match->regex);
        }
        list_destroy(conf->matchcertattrs);
        conf->matchcertattrs = NULL;
    }
}

int tlssetsni(SSL *ssl, char *sni) {
    return SSL_set_tlsext_host_name(ssl, sni); 
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
                    case SSL_ERROR_SYSCALL:
                        debugerrno(errno, DBG_ERR, "sslaccepttimeout: syscall error ");
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

/**
 * @brief read from ssl connection with timeout.
 * In case of error, ssl connection will be closed and shutdown state is set.
 * 
 * @param ssl SSL connection
 * @param buf destination buffer
 * @param num number of bytes to read
 * @param timeout maximum time to wait for data, 0 waits indefinetely
 * @param lock the lock to aquire before performing any operation on the ssl connection
 * @return number of bytes received, 0 on timeout, -1 on error (connection lost)
 */
int sslreadtimeout(SSL *ssl, unsigned char *buf, int num, int timeout, pthread_mutex_t *lock) {
    int ndesc, cnt = 0, len, sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    struct pollfd fds[1];
    unsigned long error;
    uint8_t want_write = 0;
    assert(lock);

    pthread_mutex_lock(lock);

    for (len = 0; len < num; len += cnt) {
        if (SSL_pending(ssl) == 0) {
            fds[0].fd = SSL_get_fd(ssl);
            fds[0].events = POLLIN;
            if (want_write) {
                fds[0].events |= POLLOUT;
                want_write = 0;
            }
            pthread_mutex_unlock(lock);

            ndesc = poll(fds, 1, timeout ? timeout * 1000 : -1);
            if (ndesc == 0)
                return ndesc;

            pthread_mutex_lock(lock);
            if (ndesc < 0 || fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                if (fds[0].revents & POLLERR) {
                    if(!getsockopt(SSL_get_fd(ssl), SOL_SOCKET, SO_ERROR, (void *)&sockerr, &errlen))
                        debug(DBG_INFO, "sslreadtimeout: connection lost: %s", strerror(sockerr));
                    else
                        debug(DBG_INFO, "sslreadtimeout: connection lost: unknown error");
                } else if (fds[0].revents & POLLHUP) {
                    debug(DBG_INFO, "sslreadtimeout: connection lost: hang up");
                } else if (fds[0].revents & POLLNVAL) {
                    debug(DBG_ERR, "sslreadtimeout: connection error: fd not open");
                }

                SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
                pthread_mutex_unlock(lock);
                return -1;
            }
        }

        cnt = SSL_read(ssl, buf + len, num - len);
        if (cnt <= 0) {
            switch (SSL_get_error(ssl, cnt)) {
                case SSL_ERROR_WANT_WRITE:
                    want_write = 1;
                    /* fallthrough */
                case SSL_ERROR_WANT_READ:
                    cnt = 0;
                    continue;
                case SSL_ERROR_ZERO_RETURN:
                    debug(DBG_DBG, "sslreadtimeout: got ssl shutdown");
                    SSL_shutdown(ssl);
                    break;
                case SSL_ERROR_SYSCALL:
                    if (errno)
                        debugerrno(errno, DBG_INFO, "sslreadtimeout: connection lost");
                    else
                        debug(DBG_INFO, "sslreadtimeout: connection lost: EOF");
                    /* fallthrough */
                case SSL_ERROR_SSL:
                    while ((error = ERR_get_error()))
                        debug(DBG_ERR, "sslreadtimeout: SSL: %s", ERR_error_string(error, NULL));
                    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
                    break;
                default:
                    debug(DBG_ERR, "sslreadtimeout: uncaught SSL error");
                    SSL_shutdown(ssl);
                    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            }
            pthread_mutex_unlock(lock);
            return -1;
        }
    }
    pthread_mutex_unlock(lock);
    return cnt;
}

/**
 * @brief write to a ssl session.
 * 
 * When called as blocking, it will only return once the data has been fully written,
 * an error has occured or the SSL session has been shut down.
 * 
 * @param ssl SSL session to write to
 * @param buf buffer to write
 * @param num number of bytes from buffer to write
 * @param blocking block until num bytes have been written or error occurs
 * @return int number of bytes written or 0 if it would block, or -1 on error
 */
int sslwrite(SSL *ssl, void *buf, int num, uint8_t blocking) {
    int ret = -1;
    unsigned long error;
    struct pollfd fds[1];

    uint8_t want_read = 0;

    if (!buf || num <= 0) {
        debug(DBG_ERR, "dosslwrite: was called with empty or invalid buffer!");
        return -1;
    }

    while (!SSL_get_shutdown(ssl)) {
        fds[0].fd = SSL_get_fd(ssl);
        fds[0].events = POLLOUT;
        if (want_read) {
            fds[0].events = fds[0].events | POLLIN;
            want_read = 0;
        }
        ret = poll(fds, 1, blocking ? 1000 : 0);
        if (ret == 0) {
            if (blocking) continue;
            return -1;
        }
        
        if (ret < 0 || fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            if (fds[0].revents & POLLERR) {
                debug(DBG_INFO, "sslwrite: socket error");
            } else if (fds[0].revents & POLLHUP) {
                debug(DBG_INFO, "sslwrite: socket hang up");
            } else if (fds[0].revents & POLLNVAL) {
                debug(DBG_ERR, "sslwrite: fd not open");
            }
            return -1;
        }

        if ((ret = SSL_write(ssl, buf, num)) <= 0) {
            switch (SSL_get_error(ssl, ret)) {
                case SSL_ERROR_WANT_READ:
                    want_read = 1;
                case SSL_ERROR_WANT_WRITE:
                    continue;
                default:
                    while ((error = ERR_get_error()))
                        debug(DBG_ERR, "sslwrite: SSL: %s", ERR_error_string(error, NULL));
            }
        }
        break;
    }
    return ret;
}

/**
 * @brief read radius message from ssl session
 * 
 * If errors are encountered (e.g. invalid message lengths) ssl session will be shut down)
 * All ssl operations will be performed with aquired lock.
 * Will allocate memory for buf.
 * 
 * @param ssl SSL session to read from
 * @param timeout while reading. 0 means no timeout (blocking)
 * @param lock to aquire
 * @param buf newly allocated buffer containing the read bytes
 * @return int number of bytes read, 0 on timeout or error
 */
int radtlsget(SSL *ssl, int timeout, pthread_mutex_t *lock, uint8_t **buf) {
    int cnt, len;
    unsigned char init_buf[4];

	cnt = sslreadtimeout(ssl, init_buf, 4, timeout, lock);
	if (cnt < 1)
        return 0;

    len = get_checked_rad_length(init_buf);
    if (len <= 0) {
        debug(DBG_ERR, "radtlsget: invalid message length (%d)! closing connection!", -len);
        pthread_mutex_lock(lock);
        SSL_shutdown(ssl);
        pthread_mutex_unlock(lock);
        return 0;
    }
    *buf = malloc(len);
    if (!*buf) {
        debug(DBG_ERR, "radtlsget: malloc failed! closing connection!");
        pthread_mutex_lock(lock);
        SSL_shutdown(ssl);
        pthread_mutex_unlock(lock);
        return 0;
    }
    memcpy(*buf, init_buf, 4);

    cnt = sslreadtimeout(ssl, *buf + 4, len - 4, timeout, lock);
    if (cnt < 1) {
        free(*buf);
        return 0;
    }

    debug(DBG_DBG, "radtlsget: got %d bytes", len);
    return len;
}

void *tlsserverwr(void *arg) {
    int cnt;
    struct client *client = (struct client *)arg;
    struct gqueue *replyq;
    struct request *reply;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "tlsserverwr: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));
    replyq = client->replyq;
    for (;;) {
        pthread_mutex_lock(&replyq->mutex);
        while (!list_first(replyq->entries)) {
            if (!SSL_get_shutdown(client->ssl)) {
                debug(DBG_DBG, "tlsserverwr: waiting for signal");
                pthread_cond_wait(&replyq->cond, &replyq->mutex);
                debug(DBG_DBG, "tlsserverwr: got signal");
            } else
                break;
        }

        reply = (struct request *)list_shift(replyq->entries);
        pthread_mutex_unlock(&replyq->mutex);

        pthread_mutex_lock(&client->lock);
        if (SSL_get_shutdown(client->ssl)) {
            if (reply)
                freerq(reply);
            pthread_mutex_unlock(&client->lock);
            debug(DBG_DBG, "tlsserverwr: ssl connection shutdown; exiting as requested");
            pthread_exit(NULL);
        }

        if ((cnt = sslwrite(client->ssl, reply->replybuf, reply->replybuflen, 1)) > 0) {
            debug(DBG_DBG, "tlsserverwr: sent %d bytes, Radius packet of length %d to %s",
                cnt, reply->replybuflen, addr2string(client->addr, tmp, sizeof(tmp)));
        }
        pthread_mutex_unlock(&client->lock);
    	freerq(reply);
    }
}

/**
 * @brief server read-loop for SSL sessions
 * 
 * Read radius messages from SSL session and call radsrv.
 * Write loop will be started implicitly
 * 
 * @param client the calling client
 */
void tlsserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf = NULL;
    pthread_t tlsserverwrth;
    char tmp[INET6_ADDRSTRLEN];
    int len = 0;

    debug(DBG_DBG, "tlsserverrd: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));

    if (pthread_create(&tlsserverwrth, &pthread_attr, tlsserverwr, (void *)client)) {
        debug(DBG_ERR, "tlsserverrd: pthread_create failed");
        return;
    }

    for (;;) {
        len = radtlsget(client->ssl, IDLE_TIMEOUT * 3, &client->lock, &buf);
        if (!buf || !len) {
            pthread_mutex_lock(&client->lock);
            if (SSL_get_shutdown(client->ssl))
                debug(DBG_ERR, "tlsserverrd: connection from %s, client %s lost", addr2string(client->addr, tmp, sizeof(tmp)), client->conf->name);
            else {
                debug(DBG_WARN, "tlsserverrd: timeout from %s, client %s (no requests), closing connection", addr2string(client->addr, tmp, sizeof(tmp)), client->conf->name);
                SSL_shutdown(client->ssl);
            }
            /* ensure shutdown state is set so tlsserverwr knows it can exit*/
            SSL_set_shutdown(client->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            pthread_mutex_unlock(&client->lock);
            break;
        }
        debug(DBG_DBG, "tlsserverrd: got Radius message from %s", addr2string(client->addr, tmp, sizeof(tmp)));
        rq = newrequest();
        if (!rq) {
            free(buf);
            buf = NULL;
            continue;
        }
        rq->buf = buf;
        rq->buflen = len;
        rq->from = client;
        if (!radsrv(rq)) {
            debug(DBG_ERR, "tlsserverrd: message authentication/validation failed, closing connection from %s", addr2string(client->addr, tmp, sizeof(tmp)));
            pthread_mutex_lock(&client->lock);
            SSL_shutdown(client->ssl);
            /* ensure shutdown state is set so tlsserverwr knows it can exit*/
            SSL_set_shutdown(client->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            pthread_mutex_unlock(&client->lock);
            break;
        }
        buf = NULL;
    }

    /* signal writer so it can finish (based on SSL_shutdown) */
    pthread_mutex_lock(&client->replyq->mutex);
    pthread_cond_signal(&client->replyq->cond);
    pthread_mutex_unlock(&client->replyq->mutex);
    debug(DBG_DBG, "tlsserverrd: waiting for writer to end");
    pthread_join(tlsserverwrth, NULL);
    debug(DBG_DBG, "tlsserverrd: reader for %s exiting", addr2string(client->addr, tmp, sizeof(tmp)));
}

/**
 * @brief re-do certificate verification against (new) SSL_CTX
 * Caller must ensure thread-safety!
 *
 * @param ssl SSL connection object to verify
 * @param ssl_ctx SSL_CTX to verify against
 * @return int 1 if valid, 0 if invalid, -1 otherwise (not connected, no cert etc.)
 */
int reverifycert(SSL *ssl, SSL_CTX *ssl_ctx) {
    int result = -1;
    X509* cert = NULL;
    STACK_OF(X509) *chain = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    char *buf = NULL;

    if (!ssl || !ssl_ctx)
        return result;
    
    if ( !(store = SSL_CTX_get_cert_store(ssl_ctx)) )
        return result;

    if (!SSL_is_init_finished(ssl) || SSL_get_shutdown(ssl) != 0) {
        debug(DBG_DBG, "reverifycert: SSL object not (yet) connected");
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    } else if (! (cert = SSL_get1_peer_certificate(ssl)) ) {
#else
    } else if (! (cert = SSL_get_peer_certificate(ssl)) ) {
#endif
        debug(DBG_DBG, "reverifycert: unable to get certificate from SSL object");
    } else if (!SSL_get0_chain_certs(ssl, &chain)) {
        debug(DBG_DBG, "reverifycert: unable to get cert chain from SSL object");
    } else if (! (ctx = X509_STORE_CTX_new()) ) {
        debug(DBG_ERR, "reverifycert: failed to create X509_STORE_CTX");
    } else if (!X509_STORE_CTX_init(ctx, store, cert, chain)) {
        debug(DBG_ERR, "reverifycert: failed to init X509 store context");
    } else {
        result = X509_verify_cert(ctx);
        buf = print_x509_name(X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)));
        debug(result == 0 ? DBG_NOTICE : DBG_DBG, "reverify result: num=%d:%s:depth=%d:%s", X509_STORE_CTX_get_error(ctx),
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)),
            X509_STORE_CTX_get_error_depth(ctx), buf ? buf : "");
    }

    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    return result;
}

/**
 * @brief re-validate server certificate and terminate connection if invalid
 *
 * @param srv server to validate
 */
void terminateinvalidserver(struct server *srv) {
    if (!srv) return;

    pthread_mutex_lock(&srv->lock);
    if (!srv->ssl || !srv->conf->tlsconf) {
        pthread_mutex_unlock(&srv->lock);
        return;
    }
    pthread_mutex_lock(&srv->conf->tlsconf->lock);

    switch (reverifycert(srv->ssl, tlsgetctx(srv->conf->type, srv->conf->tlsconf))) {
        case 0:
            debug(DBG_NOTICE, "terminateinvalidserver: certificate has become invalid, terminating connection to %s",
                srv->conf->name);
            SSL_shutdown(srv->ssl);
            break;
        case 1:
            debug(DBG_DBG, "terminateinvalidserver: certificate still valid for %s, continue",
                srv->conf->name);
            break;
        default:
            debug(DBG_DBG, "terminateinvalidserver: unable to determine certificate for %s, ignoring",
                srv->conf->name);
    }
    pthread_mutex_unlock(&srv->conf->tlsconf->lock);
    pthread_mutex_unlock(&srv->lock);
}

/**
 * @brief revalidate client certificate and terminate connection if invalid
 * 
 * @param cli client to validate
 */
void terminateinvalidclient(struct client *cli) {
    char tmp[INET6_ADDRSTRLEN];

    pthread_mutex_lock(&cli->lock);
    if (!cli->ssl || !cli->conf->tlsconf) {
        pthread_mutex_unlock(&cli->lock);
        return;
    }
    pthread_mutex_lock(&cli->conf->tlsconf->lock);

    switch (reverifycert(cli->ssl, tlsgetctx(cli->conf->type, cli->conf->tlsconf))) {
        case 0:
            debug(DBG_NOTICE, "terminateinvalidclient: certificate has become invalid, terminating connection from %s (%s)", 
                cli->conf->name, addr2string(cli->addr, tmp, sizeof(tmp)));
            SSL_shutdown(cli->ssl);
            break;
        case 1:
            debug(DBG_DBG, "terminateinvalidclient: certificate still valid for %s (%s), continue",
                cli->conf->name, addr2string(cli->addr, tmp, sizeof(tmp)));
            break;
        default:
            debug(DBG_DBG, "terminateinvalidclient: unable to determine certificate for %s (%s), ignoring",
                cli->conf->name, addr2string(cli->addr, tmp, sizeof(tmp)));
    }
    pthread_mutex_unlock(&cli->conf->tlsconf->lock);
    pthread_mutex_unlock(&cli->lock);
}

#else
/* Just to make the file non-empty, should rather avoid compiling this file when not needed */
typedef int make_compilers_happy;
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
