/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#ifdef SYS_SOLARIS9
#include <fcntl.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
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
#include <openssl/hmac.h>
#include <openssl/x509v3.h>
#include "debug.h"
#include "list.h"
#include "hash.h"
#include "util.h"
#include "gconfig.h"
#include "radsecproxy.h"

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

static struct hash *tlsconfs = NULL;

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
	ctx = SSL_CTX_new(TLSv1_method());
#ifdef DEBUG	
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
#endif	
	break;
#endif	
#ifdef RADPROT_DTLS	
    case RAD_DTLS:
	ctx = SSL_CTX_new(DTLSv1_method());
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
#else
/* Just to makes file non-empty, should rather avoid compiling this file when not needed */
static void tlsdummy() {
}
#endif
