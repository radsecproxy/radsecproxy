/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2011, NORDUnet A/S */
/* See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
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
#include <openssl/x509v3.h>
#include "debug.h"
#include "list.h"
#include "hash.h"
#include "util.h"
#include "hostport_types.h"
#include "radsecproxy.h"

static struct hash *tlsconfs = NULL;

void ssl_init(void) {
    time_t t;
    pid_t pid;

    SSL_load_error_strings();
    SSL_library_init();

    while (!RAND_status()) {
	t = time(NULL);
	pid = getpid();
	RAND_seed((unsigned char *)&t, sizeof(time_t));
	RAND_seed((unsigned char *)&pid, sizeof(pid));
    }
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
	break;
#endif
#ifdef RADPROT_DTLS
    case RAD_DTLS:
	ctx = SSL_CTX_new(DTLSv1_method());
	SSL_CTX_set_read_ahead(ctx, 1);
	break;
#endif
    }
    if (!ctx) {
	debug(DBG_ERR, "tlscreatectx: Error initialising SSL/TLS in TLS context %s", conf->name);
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
	return NULL;
    }
#ifdef DEBUG
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
#endif

    if (conf->certkeypwd) {
	SSL_CTX_set_default_passwd_cb_userdata(ctx, conf->certkeypwd);
	SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    }
    if (conf->certfile || conf->certkeyfile) {
	if (!SSL_CTX_use_certificate_chain_file(ctx, conf->certfile) ||
	    !SSL_CTX_use_PrivateKey_file(ctx, conf->certkeyfile, SSL_FILETYPE_PEM) ||
	    !SSL_CTX_check_private_key(ctx)) {
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
	    debug(DBG_ERR, "tlscreatectx: Error initialising SSL/TLS (certfile issues) in TLS context %s", conf->name);
	    SSL_CTX_free(ctx);
	    return NULL;
	}
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

    if (conf->cacertfile != NULL || conf->cacertpath != NULL)
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

int subjectaltnameaddr(X509 *cert, int family, const struct in6_addr *addr) {
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
	v = (char *)ASN1_STRING_data(gn->d.ia5);
	l = ASN1_STRING_length(gn->d.ia5);
	if (((family == AF_INET && l == sizeof(struct in_addr)) || (family == AF_INET6 && l == sizeof(struct in6_addr)))
	    && !memcmp(v, &addr, l)) {
	    r = 1;
	    break;
	}
    }
    GENERAL_NAMES_free(alt);
    return r;
}

int subjectaltnameregexp(X509 *cert, int type, const char *exact,  const regex_t *regex) {
    int loc, i, l, n, r = 0;
    char *s, *v;
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
	v = (char *)ASN1_STRING_data(gn->d.ia5);
	l = ASN1_STRING_length(gn->d.ia5);
	if (l <= 0)
	    continue;
#ifdef DEBUG
	printfchars(NULL, gn->type == GEN_DNS ? "dns" : "uri", NULL, v, l);
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
	    if (regexec(regex, s, 0, NULL, 0)) {
		free(s);
		continue;
	    }
	    free(s);
	}
	r = 1;
	break;
    }
    GENERAL_NAMES_free(alt);
    return r;
}

int cnregexp(X509 *cert, const char *exact, const regex_t *regex) {
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
	v = (char *) ASN1_STRING_data(t);
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
    if (conf->certnamecheck) {
	if (!certnamecheck(cert, conf->hostports)) {
	    debug(DBG_WARN, "verifyconfcert: certificate name check failed");
	    return 0;
	}
	debug(DBG_WARN, "verifyconfcert: certificate name check ok");
    }
    if (conf->certcnregex) {
	if (cnregexp(cert, NULL, conf->certcnregex) < 1) {
	    debug(DBG_WARN, "verifyconfcert: CN not matching regex");
	    return 0;
	}
	debug(DBG_DBG, "verifyconfcert: CN matching regex");
    }
    if (conf->certuriregex) {
	if (subjectaltnameregexp(cert, GEN_URI, NULL, conf->certuriregex) < 1) {
	    debug(DBG_WARN, "verifyconfcert: subjectaltname URI not matching regex");
	    return 0;
	}
	debug(DBG_DBG, "verifyconfcert: subjectaltname URI matching regex");
    }
    return 1;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
