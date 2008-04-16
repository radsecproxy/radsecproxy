/*
 * Copyright (C) 2006, 2007 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

/* For UDP there is one server instance consisting of udpserverrd and udpserverth
 *              rd is responsible for init and launching wr
 * For TLS there is a server instance that launches tlsserverrd for each TLS peer
 *          each tlsserverrd launches tlsserverwr
 * For each UDP/TLS peer there is clientrd and clientwr, clientwr is responsible
 *          for init and launching rd
 *
 * serverrd will receive a request, processes it and puts it in the requestq of
 *          the appropriate clientwr
 * clientwr monitors its requestq and sends requests
 * clientrd looks for responses, processes them and puts them in the replyq of
 *          the peer the request came from
 * serverwr monitors its reply and sends replies
 *
 * In addition to the main thread, we have:
 * If UDP peers are configured, there will be 2 + 2 * #peers UDP threads
 * If TLS peers are configured, there will initially be 2 * #peers TLS threads
 * For each TLS peer connecting to us there will be 2 more TLS threads
 *       This is only for connected peers
 * Example: With 3 UDP peer and 30 TLS peers, there will be a max of
 *          1 + (2 + 2 * 3) + (2 * 30) + (2 * 30) = 129 threads
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
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
#include "radsecproxy.h"

static struct options options;
static struct client *clients = NULL;
static struct server *servers = NULL;
static struct realm *realms = NULL;
static struct tls *tlsconfs = NULL;

static int client_udp_count = 0;
static int client_tls_count = 0;
static int client_count = 0;
static int server_udp_count = 0;
static int server_tls_count = 0;
static int server_count = 0;
static int realm_count = 0;
static int tls_count = 0;

static struct peer *tcp_server_listen;
static struct peer *udp_server_listen;
static struct replyq udp_server_replyq;
static int udp_server_sock = -1;
static pthread_mutex_t *ssl_locks;
static long *ssl_lock_count;
extern int optind;
extern char *optarg;

/* callbacks for making OpenSSL thread safe */
unsigned long ssl_thread_id() {
        return (unsigned long)pthread_self();
}

void ssl_locking_callback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
	pthread_mutex_lock(&ssl_locks[type]);
	ssl_lock_count[type]++;
    } else
	pthread_mutex_unlock(&ssl_locks[type]);
}

static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    int pwdlen = strlen(userdata);
    if (rwflag != 0 || pwdlen > size) /* not for decryption or too large */
	return 0;
    memcpy(buf, userdata, pwdlen);
    return pwdlen;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx) {
  char buf[256];
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
      X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
      debug(DBG_WARN, "verify error: num=%d:%s:depth=%d:%s", err, X509_verify_cert_error_string(err), depth, buf);

      switch (err) {
      case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	  X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
	  debug(DBG_WARN, "\tIssuer=%s", buf);
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
      }
  }
#ifdef DEBUG  
  printf("certificate verify returns %d\n", ok);
#endif  
  return ok;
}

int resolvepeer(struct peer *peer, int ai_flags) {
    struct addrinfo hints, *addrinfo;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = (peer->type == 'T' ? SOCK_STREAM : SOCK_DGRAM);
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = ai_flags;
    if (getaddrinfo(peer->host, peer->port, &hints, &addrinfo)) {
	debug(DBG_WARN, "resolvepeer: can't resolve %s port %s", peer->host, peer->port);
	return 0;
    }

    if (peer->addrinfo)
	freeaddrinfo(peer->addrinfo);
    peer->addrinfo = addrinfo;
    return 1;
}	  

int connecttoserver(struct addrinfo *addrinfo) {
    int s;
    struct addrinfo *res;

    s = -1;
    for (res = addrinfo; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            debug(DBG_WARN, "connecttoserver: socket failed");
            continue;
        }
        if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
            break;
        debug(DBG_WARN, "connecttoserver: connect failed");
        close(s);
        s = -1;
    }
    return s;
}	  

int bindtoaddr(struct addrinfo *addrinfo) {
    int s, on = 1;
    struct addrinfo *res;
    
    for (res = addrinfo; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            debug(DBG_WARN, "bindtoaddr: socket failed");
            continue;
        }
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (!bind(s, res->ai_addr, res->ai_addrlen))
	    return s;
	debug(DBG_WARN, "bindtoaddr: bind failed");
        close(s);
    }
    return -1;
}	  

/* returns the client with matching address, or NULL */
/* if client argument is not NULL, we only check that one client */
struct client *find_client(char type, struct sockaddr *addr, struct client *client) {
    struct sockaddr_in6 *sa6 = NULL;
    struct in_addr *a4 = NULL;
    struct client *c;
    int i;
    struct addrinfo *res;

    if (addr->sa_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
            a4 = (struct in_addr *)&sa6->sin6_addr.s6_addr[12];
    } else
	a4 = &((struct sockaddr_in *)addr)->sin_addr;

    c = (client ? client : clients);
    for (i = 0; i < client_count; i++) {
	if (c->peer.type == type)
	    for (res = c->peer.addrinfo; res; res = res->ai_next)
		if ((a4 && res->ai_family == AF_INET &&
		     !memcmp(a4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4)) ||
		    (sa6 && res->ai_family == AF_INET6 &&
		     !memcmp(&sa6->sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, 16)))
		    return c;
	if (client)
	    break;
	c++;
    }
    return NULL;
}

/* returns the server with matching address, or NULL */
/* if server argument is not NULL, we only check that one server */
struct server *find_server(char type, struct sockaddr *addr, struct server *server) {
    struct sockaddr_in6 *sa6 = NULL;
    struct in_addr *a4 = NULL;
    struct server *s;
    int i;
    struct addrinfo *res;

    if (addr->sa_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
            a4 = (struct in_addr *)&sa6->sin6_addr.s6_addr[12];
    } else
	a4 = &((struct sockaddr_in *)addr)->sin_addr;

    s = (server ? server : servers);
    for (i = 0; i < server_count; i++) {
	if (s->peer.type == type)
	    for (res = s->peer.addrinfo; res; res = res->ai_next)
		if ((a4 && res->ai_family == AF_INET &&
		     !memcmp(a4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4)) ||
		    (sa6 && res->ai_family == AF_INET6 &&
		     !memcmp(&sa6->sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, 16)))
		    return s;
	if (server)
	    break;
	s++;
    }
    return NULL;
}

/* exactly one of client and server must be non-NULL */
/* if *peer == NULL we return who we received from, else require it to be from peer */
/* return from in sa if not NULL */
unsigned char *radudpget(int s, struct client **client, struct server **server, struct sockaddr_storage *sa) {
    int cnt, len;
    void *f;
    unsigned char buf[65536], *rad;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);

    for (;;) {
	cnt = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
	if (cnt == -1) {
	    debug(DBG_WARN, "radudpget: recv failed");
	    continue;
	}
	debug(DBG_DBG, "radudpget: got %d bytes from %s", cnt, addr2string((struct sockaddr *)&from, fromlen));

	if (cnt < 20) {
	    debug(DBG_WARN, "radudpget: packet too small");
	    continue;
	}
    
	len = RADLEN(buf);
	if (len < 20) {
	    debug(DBG_WARN, "radudpget: length too small");
	    continue;
	}

	if (cnt < len) {
	    debug(DBG_WARN, "radudpget: packet smaller than length field in radius header");
	    continue;
	}
	if (cnt > len)
	    debug(DBG_DBG, "radudpget: packet was padded with %d bytes", cnt - len);

	f = (client
	     ? (void *)find_client('U', (struct sockaddr *)&from, *client)
	     : (void *)find_server('U', (struct sockaddr *)&from, *server));
	if (!f) {
	    debug(DBG_WARN, "radudpget: got packet from wrong or unknown UDP peer, ignoring");
	    continue;
	}

	rad = malloc(len);
	if (rad)
	    break;
	debug(DBG_ERR, "radudpget: malloc failed");
    }
    memcpy(rad, buf, len);
    if (client)
	*client = (struct client *)f; /* only need this if *client == NULL, but if not NULL *client == f here */
    else
	*server = (struct server *)f; /* only need this if *server == NULL, but if not NULL *server == f here */
    if (sa)
	*sa = from;
    return rad;
}

int subjectaltnameaddr(X509 *cert, int family, struct in6_addr *addr) {
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

int subjectaltnameregexp(X509 *cert, int type, char *exact,  regex_t *regex) {
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

int tlsverifycert(struct peer *peer) {
    int l, loc, r;
    X509 *cert;
    X509_NAME *nm;
    X509_NAME_ENTRY *e;
    ASN1_STRING *s;
    char *v;
    uint8_t type = 0; /* 0 for DNS, AF_INET for IPv4, AF_INET6 for IPv6 */
    unsigned long error;
    struct in6_addr addr;
    
    if (SSL_get_verify_result(peer->ssl) != X509_V_OK) {
	debug(DBG_ERR, "tlsverifycert: basic validation failed");
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "tlsverifycert: TLS: %s", ERR_error_string(error, NULL));
	return 0;
    }

    cert = SSL_get_peer_certificate(peer->ssl);
    if (!cert) {
	debug(DBG_ERR, "tlsverifycert: failed to obtain certificate");
	return 0;
    }

    if (inet_pton(AF_INET, peer->host, &addr))
	type = AF_INET;
    else if (inet_pton(AF_INET6, peer->host, &addr))
	type = AF_INET6;

    r = type ? subjectaltnameaddr(cert, type, &addr) : subjectaltnameregexp(cert, GEN_DNS, peer->host, NULL);
    if (r) {
	if (r < 0) {
	    X509_free(cert);
	    debug(DBG_DBG, "tlsverifycert: No subjectaltname matching %s %s", type ? "address" : "host", peer->host);
	    return 0;
	}
	debug(DBG_DBG, "tlsverifycert: Found subjectaltname matching %s %s", type ? "address" : "host", peer->host);
    } else {
	nm = X509_get_subject_name(cert);
	loc = -1;
	for (;;) {
	    loc = X509_NAME_get_index_by_NID(nm, NID_commonName, loc);
	    if (loc == -1)
		break;
	    e = X509_NAME_get_entry(nm, loc);
	    s = X509_NAME_ENTRY_get_data(e);
	    v = (char *) ASN1_STRING_data(s);
	    l = ASN1_STRING_length(s);
	    if (l < 0)
		continue;
#ifdef DEBUG
	    printfchars(NULL, "cn", NULL, v, l);
#endif	
	    if (l == strlen(peer->host) && !strncasecmp(peer->host, v, l)) {
		r = 1;
		debug(DBG_DBG, "tlsverifycert: Found cn matching host %s, All OK", peer->host);
		break;
	    }
	}
	if (!r) {
	    X509_free(cert);
	    debug(DBG_ERR, "tlsverifycert: cn not matching host %s", peer->host);
	    return 0;
	}
    }
    if (peer->certuriregex) {
        r = subjectaltnameregexp(cert, GEN_URI, NULL, peer->certuriregex);
        if (r < 1) {
            debug(DBG_DBG, "tlsverifycert: subjectaltname URI not matching regex");
            X509_free(cert);
            return 0;
        }
        debug(DBG_DBG, "tlsverifycert: subjectaltname URI matching regex");
    }
    X509_free(cert);
    return 1;
}

void tlsconnect(struct server *server, struct timeval *when, char *text) {
    struct timeval now;
    time_t elapsed;

    debug(DBG_DBG, "tlsconnect called from %s", text);
    pthread_mutex_lock(&server->lock);
    if (when && memcmp(&server->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	debug(DBG_DBG, "tlsconnect(%s): seems already reconnected", text);
	pthread_mutex_unlock(&server->lock);
	return;
    }

    debug(DBG_DBG, "tlsconnect %s", text);

    for (;;) {
	gettimeofday(&now, NULL);
	elapsed = now.tv_sec - server->lastconnecttry.tv_sec;
	if (server->connectionok) {
	    server->connectionok = 0;
	    sleep(10);
	} else if (elapsed < 5)
	    sleep(10);
	else if (elapsed < 300) {
	    debug(DBG_INFO, "tlsconnect: sleeping %lds", elapsed);
	    sleep(elapsed);
	} else if (elapsed < 100000) {
	    debug(DBG_INFO, "tlsconnect: sleeping %ds", 600);
	    sleep(600);
	} else
	    server->lastconnecttry.tv_sec = now.tv_sec;  /* no sleep at startup */
	debug(DBG_WARN, "tlsconnect: trying to open TLS connection to %s port %s", server->peer.host, server->peer.port);
	if (server->sock >= 0)
	    close(server->sock);
	if ((server->sock = connecttoserver(server->peer.addrinfo)) < 0) {
	    debug(DBG_ERR, "tlsconnect: connecttoserver failed");
	    continue;
	}
	
	SSL_free(server->peer.ssl);
	server->peer.ssl = SSL_new(server->peer.ssl_ctx);
	SSL_set_fd(server->peer.ssl, server->sock);
	if (SSL_connect(server->peer.ssl) > 0 && tlsverifycert(&server->peer))
	    break;
    }
    debug(DBG_WARN, "tlsconnect: TLS connection to %s port %s up", server->peer.host, server->peer.port);
    gettimeofday(&server->lastconnecttry, NULL);
    pthread_mutex_unlock(&server->lock);
}

unsigned char *radtlsget(SSL *ssl) {
    int cnt, total, len;
    unsigned char buf[4], *rad;

    for (;;) {
	for (total = 0; total < 4; total += cnt) {
	    cnt = SSL_read(ssl, buf + total, 4 - total);
	    if (cnt <= 0) {
		debug(DBG_ERR, "radtlsget: connection lost");
		if (SSL_get_error(ssl, cnt) == SSL_ERROR_ZERO_RETURN) {
		    /* remote end sent close_notify, send one back */
		    SSL_shutdown(ssl);
		}
		return NULL;
	    }
	}

	len = RADLEN(buf);
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "radtlsget: malloc failed");
	    continue;
	}
	memcpy(rad, buf, 4);

	for (; total < len; total += cnt) {
	    cnt = SSL_read(ssl, rad + total, len - total);
	    if (cnt <= 0) {
		debug(DBG_ERR, "radtlsget: connection lost");
		if (SSL_get_error(ssl, cnt) == SSL_ERROR_ZERO_RETURN) {
		    /* remote end sent close_notify, send one back */
		    SSL_shutdown(ssl);
		}
		free(rad);
		return NULL;
	    }
	}
    
	if (total >= 20)
	    break;
	
	free(rad);
	debug(DBG_WARN, "radtlsget: packet smaller than minimum radius size");
    }
    
    debug(DBG_DBG, "radtlsget: got %d bytes", total);
    return rad;
}

int clientradput(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct timeval lastconnecttry;
    
    len = RADLEN(rad);
    if (server->peer.type == 'U') {
	if (send(server->sock, rad, len, 0) >= 0) {
	    debug(DBG_DBG, "clienradput: sent UDP of length %d to %s port %s", len, server->peer.host, server->peer.port);
	    return 1;
	}
	debug(DBG_WARN, "clientradput: send failed");
	return 0;
    }

    lastconnecttry = server->lastconnecttry;
    while ((cnt = SSL_write(server->peer.ssl, rad, len)) <= 0) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "clientradput: TLS: %s", ERR_error_string(error, NULL));
	tlsconnect(server, &lastconnecttry, "clientradput");
	lastconnecttry = server->lastconnecttry;
    }

    server->connectionok = 1;
    debug(DBG_DBG, "clientradput: Sent %d bytes, Radius packet of length %d to TLS peer %s",
	   cnt, len, server->peer.host);
    return 1;
}

int radsign(unsigned char *rad, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned int md_len;
    int result;
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    result = (EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) &&
	EVP_DigestUpdate(&mdctx, rad, RADLEN(rad)) &&
	EVP_DigestUpdate(&mdctx, sec, strlen((char *)sec)) &&
	EVP_DigestFinal_ex(&mdctx, rad + 4, &md_len) &&
	md_len == 16);
    pthread_mutex_unlock(&lock);
    return result;
}

int validauth(unsigned char *rad, unsigned char *reqauth, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    int result;
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    len = RADLEN(rad);
    
    result = (EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) &&
	      EVP_DigestUpdate(&mdctx, rad, 4) &&
	      EVP_DigestUpdate(&mdctx, reqauth, 16) &&
	      (len <= 20 || EVP_DigestUpdate(&mdctx, rad + 20, len - 20)) &&
	      EVP_DigestUpdate(&mdctx, sec, strlen((char *)sec)) &&
	      EVP_DigestFinal_ex(&mdctx, hash, &len) &&
	      len == 16 &&
	      !memcmp(hash, rad + 4, 16));
    pthread_mutex_unlock(&lock);
    return result;
}
	      
int checkmessageauth(unsigned char *rad, uint8_t *authattr, char *secret) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static HMAC_CTX hmacctx;
    unsigned int md_len;
    uint8_t auth[16], hash[EVP_MAX_MD_SIZE];
    
    pthread_mutex_lock(&lock);
    if (first) {
	HMAC_CTX_init(&hmacctx);
	first = 0;
    }

    memcpy(auth, authattr, 16);
    memset(authattr, 0, 16);
    md_len = 0;
    HMAC_Init_ex(&hmacctx, secret, strlen(secret), EVP_md5(), NULL);
    HMAC_Update(&hmacctx, rad, RADLEN(rad));
    HMAC_Final(&hmacctx, hash, &md_len);
    memcpy(authattr, auth, 16);
    if (md_len != 16) {
	debug(DBG_WARN, "message auth computation failed");
	pthread_mutex_unlock(&lock);
	return 0;
    }

    if (memcmp(auth, hash, 16)) {
	debug(DBG_WARN, "message authenticator, wrong value");
	pthread_mutex_unlock(&lock);
	return 0;
    }	
	
    pthread_mutex_unlock(&lock);
    return 1;
}

int createmessageauth(unsigned char *rad, unsigned char *authattrval, char *secret) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static HMAC_CTX hmacctx;
    unsigned int md_len;

    if (!authattrval)
	return 1;
    
    pthread_mutex_lock(&lock);
    if (first) {
	HMAC_CTX_init(&hmacctx);
	first = 0;
    }

    memset(authattrval, 0, 16);
    md_len = 0;
    HMAC_Init_ex(&hmacctx, secret, strlen(secret), EVP_md5(), NULL);
    HMAC_Update(&hmacctx, rad, RADLEN(rad));
    HMAC_Final(&hmacctx, authattrval, &md_len);
    if (md_len != 16) {
	debug(DBG_WARN, "message auth computation failed");
	pthread_mutex_unlock(&lock);
	return 0;
    }

    pthread_mutex_unlock(&lock);
    return 1;
}

unsigned char *attrget(unsigned char *attrs, int length, uint8_t type) {
    while (length > 1) {
	if (ATTRTYPE(attrs) == type)
	    return attrs;
	length -= ATTRLEN(attrs);
	attrs += ATTRLEN(attrs);
    }
    return NULL;
}

void sendrq(struct server *to, struct request *rq) {
    int i;
    uint8_t *attr;

    pthread_mutex_lock(&to->newrq_mutex);
    /* might simplify if only try nextid, might be ok */
    for (i = to->nextid; i < MAX_REQUESTS; i++)
	if (!to->requests[i].buf)
	    break;
    if (i == MAX_REQUESTS) {
	for (i = 0; i < to->nextid; i++)
	    if (!to->requests[i].buf)
		break;
	if (i == to->nextid) {
	    debug(DBG_WARN, "No room in queue, dropping request");
	    free(rq->buf);
	    pthread_mutex_unlock(&to->newrq_mutex);
	    return;
	}
    }
    
    rq->buf[1] = (char)i;

    attr = attrget(rq->buf + 20, RADLEN(rq->buf) - 20, RAD_Attr_Message_Authenticator);
    if (attr && !createmessageauth(rq->buf, ATTRVAL(attr), to->peer.secret)) {
	free(rq->buf);
	pthread_mutex_unlock(&to->newrq_mutex);
	return;
    }

    debug(DBG_DBG, "sendrq: inserting packet with id %d in queue for %s", i, to->peer.host);
    to->requests[i] = *rq;
    to->nextid = i + 1;

    if (!to->newrq) {
	to->newrq = 1;
	debug(DBG_DBG, "signalling client writer");
	pthread_cond_signal(&to->newrq_cond);
    }
    pthread_mutex_unlock(&to->newrq_mutex);
}

void sendreply(struct client *to, unsigned char *buf, struct sockaddr_storage *tosa) {
    struct replyq *replyq = to->replyq;
    
    if (!radsign(buf, (unsigned char *)to->peer.secret)) {
	free(buf);
	debug(DBG_WARN, "sendreply: failed to sign message");
	return;
    }
	
    pthread_mutex_lock(&replyq->count_mutex);
    if (replyq->count == replyq->size) {
	debug(DBG_WARN, "No room in queue, dropping request");
	pthread_mutex_unlock(&replyq->count_mutex);
	free(buf);
	return;
    }

    replyq->replies[replyq->count].buf = buf;
    if (tosa)
	replyq->replies[replyq->count].tosa = *tosa;
    replyq->count++;

    if (replyq->count == 1) {
	debug(DBG_DBG, "signalling server writer");
	pthread_cond_signal(&replyq->count_cond);
    }
    pthread_mutex_unlock(&replyq->count_mutex);
}

int pwdencrypt(uint8_t *in, uint8_t len, char *shared, uint8_t sharedlen, uint8_t *auth) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE], *input;
    unsigned int md_len;
    uint8_t i, offset = 0, out[128];
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    input = auth;
    for (;;) {
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, (uint8_t *)shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, input, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
	for (i = 0; i < 16; i++)
	    out[offset + i] = hash[i] ^ in[offset + i];
	input = out + offset - 16;
	offset += 16;
	if (offset == len)
	    break;
    }
    memcpy(in, out, len);
    pthread_mutex_unlock(&lock);
    return 1;
}

int pwddecrypt(uint8_t *in, uint8_t len, char *shared, uint8_t sharedlen, uint8_t *auth) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE], *input;
    unsigned int md_len;
    uint8_t i, offset = 0, out[128];
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    input = auth;
    for (;;) {
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, (uint8_t *)shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, input, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
	for (i = 0; i < 16; i++)
	    out[offset + i] = hash[i] ^ in[offset + i];
	input = in + offset;
	offset += 16;
	if (offset == len)
	    break;
    }
    memcpy(in, out, len);
    pthread_mutex_unlock(&lock);
    return 1;
}

int msmppencrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    uint8_t i, offset;
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

#if 0
    printfchars(NULL, "msppencrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppencrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppencrypt in", "%02x ", text, len);
#endif
    
    if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	!EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	!EVP_DigestUpdate(&mdctx, auth, 16) ||
	!EVP_DigestUpdate(&mdctx, salt, 2) ||
	!EVP_DigestFinal_ex(&mdctx, hash, &md_len)) {
	pthread_mutex_unlock(&lock);
	return 0;
    }

#if 0
    printfchars(NULL, "msppencrypt hash", "%02x ", hash, 16);
#endif
    
    for (i = 0; i < 16; i++)
	text[i] ^= hash[i];
    
    for (offset = 16; offset < len; offset += 16) {
#if 0	
	printf("text + offset - 16 c(%d): ", offset / 16);
	printfchars(NULL, NULL, "%02x ", text + offset - 16, 16);
#endif
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, text + offset - 16, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
#if 0
	printfchars(NULL, "msppencrypt hash", "%02x ", hash, 16);
#endif    
	
	for (i = 0; i < 16; i++)
	    text[offset + i] ^= hash[i];
    }
    
#if 0
    printfchars(NULL, "msppencrypt out", "%02x ", text, len);
#endif

    pthread_mutex_unlock(&lock);
    return 1;
}

int msmppdecrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    uint8_t i, offset;
    char plain[255];
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

#if 0
    printfchars(NULL, "msppdecrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppdecrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppdecrypt in", "%02x ", text, len);
#endif
    
    if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	!EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	!EVP_DigestUpdate(&mdctx, auth, 16) ||
	!EVP_DigestUpdate(&mdctx, salt, 2) ||
	!EVP_DigestFinal_ex(&mdctx, hash, &md_len)) {
	pthread_mutex_unlock(&lock);
	return 0;
    }

#if 0
    printfchars(NULL, "msppdecrypt hash", "%02x ", hash, 16);
#endif
    
    for (i = 0; i < 16; i++)
	plain[i] = text[i] ^ hash[i];
    
    for (offset = 16; offset < len; offset += 16) {
#if 0 	
	printf("text + offset - 16 c(%d): ", offset / 16);
	printfchars(NULL, "msppdecrypt hash", "%02x ", hash, 16);
#endif
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, text + offset - 16, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
#if 0
	printfchars(NULL, "msppdecrypt hash", "%02x ", hash, 16);
#endif    

	for (i = 0; i < 16; i++)
	    plain[offset + i] = text[offset + i] ^ hash[i];
    }

    memcpy(text, plain, len);
#if 0
    printfchars(NULL, "msppdecrypt out", "%02x ", text, len);
#endif

    pthread_mutex_unlock(&lock);
    return 1;
}

struct realm *id2realm(char *id, uint8_t len) {
    int i;
    for (i = 0; i < realm_count; i++)
	if (!regexec(&realms[i].regex, id, 0, NULL, 0)) {
	    debug(DBG_DBG, "found matching realm: %s", realms[i].name);
	    return realms + i;
	}
    return NULL;
}

int rqinqueue(struct server *to, struct client *from, uint8_t id) {
    int i;
    
    pthread_mutex_lock(&to->newrq_mutex);
    for (i = 0; i < MAX_REQUESTS; i++)
	if (to->requests[i].buf && !to->requests[i].received && to->requests[i].origid == id && to->requests[i].from == from)
	    break;
    pthread_mutex_unlock(&to->newrq_mutex);
    
    return i < MAX_REQUESTS;
}

int attrvalidate(unsigned char *attrs, int length) {
    while (length > 1) {
	if (ATTRLEN(attrs) < 2) {
	    debug(DBG_WARN, "attrvalidate: invalid attribute length %d", ATTRLEN(attrs));
	    return 0;
	}
	length -= ATTRLEN(attrs);
	if (length < 0) {
	    debug(DBG_WARN, "attrvalidate: attribute length %d exceeds packet length", ATTRLEN(attrs));
	    return 0;
	}
	attrs += ATTRLEN(attrs);
    }
    if (length)
	debug(DBG_WARN, "attrvalidate: malformed packet? remaining byte after last attribute");
    return 1;
}

int pwdrecrypt(uint8_t *pwd, uint8_t len, char *oldsecret, char *newsecret, uint8_t *oldauth, uint8_t *newauth) {
    if (len < 16 || len > 128 || len % 16) {
	debug(DBG_WARN, "pwdrecrypt: invalid password length");
	return 0;
    }
	
    if (!pwddecrypt(pwd, len, oldsecret, strlen(oldsecret), oldauth)) {
	debug(DBG_WARN, "pwdrecrypt: cannot decrypt password");
	return 0;
    }
#ifdef DEBUG
    printfchars(NULL, "pwdrecrypt: password", "%02x ", pwd, len);
#endif	
    if (!pwdencrypt(pwd, len, newsecret, strlen(newsecret), newauth)) {
	debug(DBG_WARN, "pwdrecrypt: cannot encrypt password");
	return 0;
    }
    return 1;
}

int msmpprecrypt(uint8_t *msmpp, uint8_t len, char *oldsecret, char *newsecret, unsigned char *oldauth, char *newauth) {
    if (len < 18)
	return 0;
    if (!msmppdecrypt(msmpp + 2, len - 2, (unsigned char *)oldsecret, strlen(oldsecret), oldauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to decrypt msppe key");
	return 0;
    }
    if (!msmppencrypt(msmpp + 2, len - 2, (unsigned char *)newsecret, strlen(newsecret), (unsigned char *)newauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to encrypt msppe key");
	return 0;
    }
    return 1;
}

int msmppe(unsigned char *attrs, int length, uint8_t type, char *attrtxt, struct request *rq,
	   char *oldsecret, char *newsecret) {
    unsigned char *attr;
    
    for (attr = attrs; (attr = attrget(attr, length - (attr - attrs), type)); attr += ATTRLEN(attr)) {
	debug(DBG_DBG, "msmppe: Got %s", attrtxt);
	if (!msmpprecrypt(ATTRVAL(attr), ATTRVALLEN(attr), oldsecret, newsecret, rq->buf + 4, rq->origauth))
	    return 0;
    }
    return 1;
}

void respondstatusserver(struct request *rq) {
    unsigned char *resp;

    resp = malloc(20);
    if (!resp) {
	debug(DBG_ERR, "respondstatusserver: malloc failed");
	return;
    }
    memcpy(resp, rq->buf, 20);
    resp[0] = RAD_Access_Accept;
    resp[2] = 0;
    resp[3] = 20;
    debug(DBG_DBG, "respondstatusserver: responding to %s", rq->from->peer.host);
    sendreply(rq->from, resp, rq->from->peer.type == 'U' ? &rq->fromsa : NULL);
}

void respondreject(struct request *rq, char *message) {
    unsigned char *resp;
    int len = 20;

    if (message)
	len += 2 + strlen(message);
    
    resp = malloc(len);
    if (!resp) {
	debug(DBG_ERR, "respondreject: malloc failed");
	return;
    }
    memcpy(resp, rq->buf, 20);
    resp[0] = RAD_Access_Reject;
    *(uint16_t *)(resp + 2) = htons(len);
    if (message) {
	resp[20] = RAD_Attr_Reply_Message;
	resp[21] = len - 20;
	memcpy(resp + 22, message, len - 22);
    }
    sendreply(rq->from, resp, rq->from->peer.type == 'U' ? &rq->fromsa : NULL);
}

void radsrv(struct request *rq) {
    uint8_t code, id, *auth, *attrs, *attr;
    uint16_t len;
    struct server *to = NULL;
    char username[256];
    unsigned char *buf, newauth[16];
    struct realm *realm = NULL;
    
    buf = rq->buf;
    code = *(uint8_t *)buf;
    id = *(uint8_t *)(buf + 1);
    len = RADLEN(buf);
    auth = (uint8_t *)(buf + 4);

    debug(DBG_DBG, "radsrv: code %d, id %d, length %d", code, id, len);
    
    if (code != RAD_Access_Request && code != RAD_Status_Server) {
	debug(DBG_INFO, "radsrv: server currently accepts only access-requests and status-server, ignoring");
	free(buf);
	return;
    }

    len -= 20;
    attrs = buf + 20;

    if (!attrvalidate(attrs, len)) {
	debug(DBG_WARN, "radsrv: attribute validation failed, ignoring packet");
	free(buf);
	return;
    }

    if (code == RAD_Access_Request) {
	attr = attrget(attrs, len, RAD_Attr_User_Name);
	if (!attr) {
	    debug(DBG_WARN, "radsrv: ignoring request, no username attribute");
	    free(buf);
	    return;
	}
	memcpy(username, ATTRVAL(attr), ATTRVALLEN(attr));
	username[ATTRVALLEN(attr)] = '\0';
	debug(DBG_DBG, "Access Request with username: %s", username);

	realm = id2realm(username, strlen(username));
	if (!realm) {
	    debug(DBG_INFO, "radsrv: ignoring request, don't know where to send it");
	    free(buf);
	    return;
	}
	to = servers + realm->serverno;

	if (to && rqinqueue(to, rq->from, id)) {
	    debug(DBG_INFO, "radsrv: already got request from host %s with id %d, ignoring", rq->from->peer.host, id);
	    free(buf);
	    return;
	}
    }
    
    attr = attrget(attrs, len, RAD_Attr_Message_Authenticator);
    if (attr && (ATTRVALLEN(attr) != 16 || !checkmessageauth(buf, ATTRVAL(attr), rq->from->peer.secret))) {
	debug(DBG_WARN, "radsrv: message authentication failed");
	free(buf);
	return;
    }
    
    if (code == RAD_Status_Server) {
	respondstatusserver(rq);
	free(buf);
	return;
    }

    if (!to) {
	debug(DBG_INFO, "radsrv: sending reject to %s for %s", rq->from->peer.host, username);
	respondreject(rq, realm->message);
	free(buf);
	return;
    }
    
    if (!RAND_bytes(newauth, 16)) {
	debug(DBG_WARN, "radsrv: failed to generate random auth");
	free(buf);
	return;
    }

#ifdef DEBUG    
    printfchars(NULL, "auth", "%02x ", auth, 16);
#endif

    attr = attrget(attrs, len, RAD_Attr_User_Password);
    if (attr) {
	debug(DBG_DBG, "radsrv: found userpwdattr with value length %d", ATTRVALLEN(attr));
	if (!pwdrecrypt(ATTRVAL(attr), ATTRVALLEN(attr), rq->from->peer.secret, to->peer.secret, auth, newauth)) {
	    free(buf);
	    return;
	}
    }
    
    attr = attrget(attrs, len, RAD_Attr_Tunnel_Password);
    if (attr) {
	debug(DBG_DBG, "radsrv: found tunnelpwdattr with value length %d", ATTRVALLEN(attr));
	if (!pwdrecrypt(ATTRVAL(attr), ATTRVALLEN(attr), rq->from->peer.secret, to->peer.secret, auth, newauth)) {
	    free(buf);
	    return;
	}
    }

    rq->origid = id;
    memcpy(rq->origauth, auth, 16);
    memcpy(auth, newauth, 16);
    sendrq(to, rq);
}

void *clientrd(void *arg) {
    struct server *server = (struct server *)arg;
    struct client *from;
    int i, len, sublen;
    unsigned char *buf, *messageauth, *subattrs, *attrs, *attr;
    struct sockaddr_storage fromsa;
    struct timeval lastconnecttry;
    char tmp[256];
    
    for (;;) {
	lastconnecttry = server->lastconnecttry;
	buf = (server->peer.type == 'U' ? radudpget(server->sock, NULL, &server, NULL) : radtlsget(server->peer.ssl));
	if (!buf && server->peer.type == 'T') {
	    tlsconnect(server, &lastconnecttry, "clientrd");
	    continue;
	}
    
	server->connectionok = 1;

	i = buf[1]; /* i is the id */

	switch (*buf) {
	case RAD_Access_Accept:
	    debug(DBG_DBG, "got Access Accept with id %d", i);
	    break;
	case RAD_Access_Reject:
	    debug(DBG_DBG, "got Access Reject with id %d", i);
	    break;
	case RAD_Access_Challenge:
	    debug(DBG_DBG, "got Access Challenge with id %d", i);
	    break;
	default:
	    free(buf);
	    debug(DBG_INFO, "clientrd: discarding, only accept access accept, access reject and access challenge messages");
	    continue;
	}
	
	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->requests[i].buf || !server->requests[i].tries) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    free(buf);
	    debug(DBG_INFO, "clientrd: no matching request sent with this id, ignoring");
	    continue;
	}

	if (server->requests[i].received) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    free(buf);
	    debug(DBG_INFO, "clientrd: already received, ignoring");
	    continue;
	}
	
	if (!validauth(buf, server->requests[i].buf + 4, (unsigned char *)server->peer.secret)) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    free(buf);
	    debug(DBG_WARN, "clientrd: invalid auth, ignoring");
	    continue;
	}
	
	from = server->requests[i].from;
	len = RADLEN(buf) - 20;
	attrs = buf + 20;

	if (!attrvalidate(attrs, len)) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    free(buf);
	    debug(DBG_WARN, "clientrd: attribute validation failed, ignoring packet");
	    continue;
	}
	
	/* Message Authenticator */
	messageauth = attrget(attrs, len, RAD_Attr_Message_Authenticator);
	if (messageauth) {
	    if (ATTRVALLEN(messageauth) != 16) {
		pthread_mutex_unlock(&server->newrq_mutex);
		free(buf);
		debug(DBG_WARN, "clientrd: illegal message auth attribute length, ignoring packet");
		continue;
	    }
	    memcpy(tmp, buf + 4, 16);
	    memcpy(buf + 4, server->requests[i].buf + 4, 16);
	    if (!checkmessageauth(buf, ATTRVAL(messageauth), server->peer.secret)) {
		pthread_mutex_unlock(&server->newrq_mutex);
		free(buf);
		debug(DBG_WARN, "clientrd: message authentication failed");
		continue;
	    }
	    memcpy(buf + 4, tmp, 16);
	    debug(DBG_DBG, "clientrd: message auth ok");
	}
	
	if (*server->requests[i].buf == RAD_Status_Server) {
	    server->requests[i].received = 1;
	    pthread_mutex_unlock(&server->newrq_mutex);
	    free(buf);
	    debug(DBG_INFO, "clientrd: got status server response from %s", server->peer.host);
	    continue;
	}

	/* MS MPPE */
	for (attr = attrs; (attr = attrget(attr, len - (attr - attrs), RAD_Attr_Vendor_Specific)); attr += ATTRLEN(attr)) {
	    if (ATTRVALLEN(attr) <= 4)
		break;
	    
	    if (attr[2] != 0 || attr[3] != 0 || attr[4] != 1 || attr[5] != 55)  /* 311 == MS */
		continue;
	    
	    sublen = ATTRVALLEN(attr) - 4;
	    subattrs = ATTRVAL(attr) + 4;  
	    if (!attrvalidate(subattrs, sublen) ||
		!msmppe(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Send_Key, "MS MPPE Send Key",
			server->requests + i, server->peer.secret, from->peer.secret) ||
		!msmppe(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Recv_Key, "MS MPPE Recv Key",
			server->requests + i, server->peer.secret, from->peer.secret))
		break;
	}
	if (attr) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    free(buf);
	    debug(DBG_WARN, "clientrd: MS attribute handling failed, ignoring packet");
	    continue;
	}
	
	if (*buf == RAD_Access_Accept || *buf == RAD_Access_Reject) {
	    attr = attrget(server->requests[i].buf + 20, RADLEN(server->requests[i].buf) - 20, RAD_Attr_User_Name);
	    /* we know the attribute exists */
	    memcpy(tmp, ATTRVAL(attr), ATTRVALLEN(attr));
	    tmp[ATTRVALLEN(attr)] = '\0';
	    switch (*buf) {
	    case RAD_Access_Accept:
		debug(DBG_INFO, "Access Accept for %s from %s", tmp, server->peer.host);
		break;
	    case RAD_Access_Reject:
		debug(DBG_INFO, "Access Reject for %s from %s", tmp, server->peer.host);
		break;
	    }
	}
	
	/* once we set received = 1, requests[i] may be reused */
	buf[1] = (char)server->requests[i].origid;
	memcpy(buf + 4, server->requests[i].origauth, 16);
#ifdef DEBUG	
	printfchars(NULL, "origauth/buf+4", "%02x ", buf + 4, 16);
#endif
	
	if (messageauth) {
	    if (!createmessageauth(buf, ATTRVAL(messageauth), from->peer.secret)) {
		pthread_mutex_unlock(&server->newrq_mutex);
		free(buf);
		continue;
	    }
	    debug(DBG_DBG, "clientrd: computed messageauthattr");
	}

	if (from->peer.type == 'U')
	    fromsa = server->requests[i].fromsa;
	server->requests[i].received = 1;
	pthread_mutex_unlock(&server->newrq_mutex);

	debug(DBG_DBG, "clientrd: giving packet back to where it came from");
	sendreply(from, buf, from->peer.type == 'U' ? &fromsa : NULL);
    }
}

void *clientwr(void *arg) {
    struct server *server = (struct server *)arg;
    struct request *rq;
    pthread_t clientrdth;
    int i;
    uint8_t rnd;
    struct timeval now, lastsend;
    struct timespec timeout;
    struct request statsrvrq;
    unsigned char statsrvbuf[38];

    memset(&timeout, 0, sizeof(struct timespec));
    
    if (server->statusserver) {
	memset(&statsrvrq, 0, sizeof(struct request));
	memset(statsrvbuf, 0, sizeof(statsrvbuf));
	statsrvbuf[0] = RAD_Status_Server;
	statsrvbuf[3] = 38;
	statsrvbuf[20] = RAD_Attr_Message_Authenticator;
	statsrvbuf[21] = 18;
	gettimeofday(&lastsend, NULL);
    }
    
    if (server->peer.type == 'U') {
	if ((server->sock = connecttoserver(server->peer.addrinfo)) < 0)
	    debugx(1, DBG_ERR, "clientwr: connecttoserver failed");
    } else
	tlsconnect(server, NULL, "new client");
    
    if (pthread_create(&clientrdth, NULL, clientrd, (void *)server))
	debugx(1, DBG_ERR, "clientwr: pthread_create failed");

    for (;;) {
	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->newrq) {
	    gettimeofday(&now, NULL);
	    if (server->statusserver) {
		/* random 0-7 seconds */
		RAND_bytes(&rnd, 1);
		rnd /= 32;
		if (!timeout.tv_sec || timeout.tv_sec - now.tv_sec > lastsend.tv_sec + STATUS_SERVER_PERIOD + rnd)
		    timeout.tv_sec = lastsend.tv_sec + STATUS_SERVER_PERIOD + rnd;
	    }   
	    if (timeout.tv_sec) {
		debug(DBG_DBG, "clientwr: waiting up to %ld secs for new request", timeout.tv_sec - now.tv_sec);
		pthread_cond_timedwait(&server->newrq_cond, &server->newrq_mutex, &timeout);
		timeout.tv_sec = 0;
	    } else {
		debug(DBG_DBG, "clientwr: waiting for new request");
		pthread_cond_wait(&server->newrq_cond, &server->newrq_mutex);
	    }
	}
	if (server->newrq) {
	    debug(DBG_DBG, "clientwr: got new request");
	    server->newrq = 0;
	} else
	    debug(DBG_DBG, "clientwr: request timer expired, processing request queue");
	pthread_mutex_unlock(&server->newrq_mutex);

	for (i = 0; i < MAX_REQUESTS; i++) {
	    pthread_mutex_lock(&server->newrq_mutex);
	    while (i < MAX_REQUESTS && !server->requests[i].buf)
		i++;
	    if (i == MAX_REQUESTS) {
		pthread_mutex_unlock(&server->newrq_mutex);
		break;
	    }
	    rq = server->requests + i;

            if (rq->received) {
		debug(DBG_DBG, "clientwr: packet %d in queue is marked as received", i);
		if (rq->buf) {
		    debug(DBG_DBG, "clientwr: freeing received packet %d from queue", i);
		    free(rq->buf);
		    /* setting this to NULL means that it can be reused */
		    rq->buf = NULL;
		}
                pthread_mutex_unlock(&server->newrq_mutex);
                continue;
            }
	    
	    gettimeofday(&now, NULL);
            if (now.tv_sec < rq->expiry.tv_sec) {
		if (!timeout.tv_sec || rq->expiry.tv_sec < timeout.tv_sec)
		    timeout.tv_sec = rq->expiry.tv_sec;
		pthread_mutex_unlock(&server->newrq_mutex);
		continue;
	    }

	    if (rq->tries == (*rq->buf == RAD_Status_Server || server->peer.type == 'T'
			      ? 1 : REQUEST_RETRIES)) {
		debug(DBG_DBG, "clientwr: removing expired packet from queue");
		if (*rq->buf == RAD_Status_Server)
		    debug(DBG_WARN, "clientwr: no status server response, %s dead?", server->peer.host);
		free(rq->buf);
		/* setting this to NULL means that it can be reused */
		rq->buf = NULL;
		pthread_mutex_unlock(&server->newrq_mutex);
		continue;
	    }
            pthread_mutex_unlock(&server->newrq_mutex);

	    rq->expiry.tv_sec = now.tv_sec +
		(*rq->buf == RAD_Status_Server || server->peer.type == 'T'
		 ? REQUEST_EXPIRY : REQUEST_EXPIRY / REQUEST_RETRIES);
	    if (!timeout.tv_sec || rq->expiry.tv_sec < timeout.tv_sec)
		timeout.tv_sec = rq->expiry.tv_sec;
	    rq->tries++;
	    clientradput(server, server->requests[i].buf);
	    gettimeofday(&lastsend, NULL);
	}
	if (server->statusserver) {
	    gettimeofday(&now, NULL);
	    if (now.tv_sec - lastsend.tv_sec >= STATUS_SERVER_PERIOD) {
		if (!RAND_bytes(statsrvbuf + 4, 16)) {
		    debug(DBG_WARN, "clientwr: failed to generate random auth");
		    continue;
		}
		statsrvrq.buf = malloc(sizeof(statsrvbuf));
		if (!statsrvrq.buf) {
		    debug(DBG_ERR, "clientwr: malloc failed");
		    continue;
		}
		memcpy(statsrvrq.buf, statsrvbuf, sizeof(statsrvbuf));
		debug(DBG_DBG, "clientwr: sending status server to %s", server->peer.host);
		lastsend.tv_sec = now.tv_sec;
		sendrq(server, &statsrvrq);
	    }
	}
    }
}

void *udpserverwr(void *arg) {
    struct replyq *replyq = &udp_server_replyq;
    struct reply *reply = replyq->replies;
    
    pthread_mutex_lock(&replyq->count_mutex);
    for (;;) {
	while (!replyq->count) {
	    debug(DBG_DBG, "udp server writer, waiting for signal");
	    pthread_cond_wait(&replyq->count_cond, &replyq->count_mutex);
	    debug(DBG_DBG, "udp server writer, got signal");
	}
	pthread_mutex_unlock(&replyq->count_mutex);
	
	if (sendto(udp_server_sock, reply->buf, RADLEN(reply->buf), 0,
		   (struct sockaddr *)&reply->tosa, SOCKADDR_SIZE(reply->tosa)) < 0)
	    debug(DBG_WARN, "sendudp: send failed");
	free(reply->buf);
	
	pthread_mutex_lock(&replyq->count_mutex);
	replyq->count--;
	memmove(replyq->replies, replyq->replies + 1,
		replyq->count * sizeof(struct reply));
    }
}

void *udpserverrd(void *arg) {
    struct request rq;
    pthread_t udpserverwrth;

    if ((udp_server_sock = bindtoaddr(udp_server_listen->addrinfo)) < 0)
	debugx(1, DBG_ERR, "udpserverrd: socket/bind failed");

    debug(DBG_WARN, "udpserverrd: listening for UDP on %s:%s",
	  udp_server_listen->host ? udp_server_listen->host : "*", udp_server_listen->port);

    if (pthread_create(&udpserverwrth, NULL, udpserverwr, NULL))
	debugx(1, DBG_ERR, "pthread_create failed");
    
    for (;;) {
	memset(&rq, 0, sizeof(struct request));
	rq.buf = radudpget(udp_server_sock, &rq.from, NULL, &rq.fromsa);
	radsrv(&rq);
    }
}

void *tlsserverwr(void *arg) {
    int cnt;
    unsigned long error;
    struct client *client = (struct client *)arg;
    struct replyq *replyq;
    
    debug(DBG_DBG, "tlsserverwr starting for %s", client->peer.host);
    replyq = client->replyq;
    pthread_mutex_lock(&replyq->count_mutex);
    for (;;) {
	while (!replyq->count) {
	    if (client->peer.ssl) {	    
		debug(DBG_DBG, "tls server writer, waiting for signal");
		pthread_cond_wait(&replyq->count_cond, &replyq->count_mutex);
		debug(DBG_DBG, "tls server writer, got signal");
	    }
	    if (!client->peer.ssl) {
		/* ssl might have changed while waiting */
		pthread_mutex_unlock(&replyq->count_mutex);
		debug(DBG_DBG, "tlsserverwr: exiting as requested");
		pthread_exit(NULL);
	    }
	}
	pthread_mutex_unlock(&replyq->count_mutex);
	cnt = SSL_write(client->peer.ssl, replyq->replies->buf, RADLEN(replyq->replies->buf));
	if (cnt > 0)
	    debug(DBG_DBG, "tlsserverwr: Sent %d bytes, Radius packet of length %d",
		  cnt, RADLEN(replyq->replies->buf));
	else
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "tlsserverwr: SSL: %s", ERR_error_string(error, NULL));
	free(replyq->replies->buf);

	pthread_mutex_lock(&replyq->count_mutex);
	replyq->count--;
	memmove(replyq->replies, replyq->replies + 1, replyq->count * sizeof(struct reply));
    }
}

void *tlsserverrd(void *arg) {
    struct request rq;
    unsigned long error;
    int s;
    struct client *client = (struct client *)arg;
    pthread_t tlsserverwrth;
    SSL *ssl;
    
    debug(DBG_DBG, "tlsserverrd starting for %s", client->peer.host);
    ssl = client->peer.ssl;

    if (SSL_accept(ssl) <= 0) {
        while ((error = ERR_get_error()))
            debug(DBG_ERR, "tlsserverrd: SSL: %s", ERR_error_string(error, NULL));
        debug(DBG_ERR, "SSL_accept failed");
	goto errexit;
    }
    if (tlsverifycert(&client->peer)) {
	if (pthread_create(&tlsserverwrth, NULL, tlsserverwr, (void *)client)) {
	    debug(DBG_ERR, "tlsserverrd: pthread_create failed");
	    goto errexit;
	}
	for (;;) {
	    memset(&rq, 0, sizeof(struct request));
	    rq.buf = radtlsget(client->peer.ssl);
	    if (!rq.buf)
		break;
	    debug(DBG_DBG, "tlsserverrd: got Radius message from %s", client->peer.host);
	    rq.from = client;
	    radsrv(&rq);
	}
	debug(DBG_ERR, "tlsserverrd: connection lost");
	/* stop writer by setting peer.ssl to NULL and give signal in case waiting for data */
	client->peer.ssl = NULL;
	pthread_mutex_lock(&client->replyq->count_mutex);
	pthread_cond_signal(&client->replyq->count_cond);
	pthread_mutex_unlock(&client->replyq->count_mutex);
	debug(DBG_DBG, "tlsserverrd: waiting for writer to end");
	pthread_join(tlsserverwrth, NULL);
    }
    
 errexit:
    s = SSL_get_fd(ssl);
    SSL_free(ssl);
    shutdown(s, SHUT_RDWR);
    close(s);
    debug(DBG_DBG, "tlsserverrd thread for %s exiting", client->peer.host);
    client->peer.ssl = NULL;
    pthread_exit(NULL);
}

int tlslistener() {
    pthread_t tlsserverth;
    int s, snew;
    struct sockaddr_storage from;
    size_t fromlen = sizeof(from);
    struct client *client;

    if ((s = bindtoaddr(tcp_server_listen->addrinfo)) < 0)
        debugx(1, DBG_ERR, "tlslistener: socket/bind failed");
    
    listen(s, 0);
    debug(DBG_WARN, "listening for incoming TCP on %s:%s",
	  tcp_server_listen->host ? tcp_server_listen->host : "*", tcp_server_listen->port);

    for (;;) {
	snew = accept(s, (struct sockaddr *)&from, &fromlen);
	if (snew < 0) {
	    debug(DBG_WARN, "accept failed");
	    continue;
	}
	debug(DBG_WARN, "incoming TLS connection from %s", addr2string((struct sockaddr *)&from, fromlen));

	client = find_client('T', (struct sockaddr *)&from, NULL);
	if (!client) {
	    debug(DBG_WARN, "ignoring request, not a known TLS client");
	    shutdown(snew, SHUT_RDWR);
	    close(snew);
	    continue;
	}

	if (client->peer.ssl) {
	    debug(DBG_WARN, "Ignoring incoming TLS connection, already have one from this client");
	    shutdown(snew, SHUT_RDWR);
	    close(snew);
	    continue;
	}
	client->peer.ssl = SSL_new(client->peer.ssl_ctx);
	SSL_set_fd(client->peer.ssl, snew);
	if (pthread_create(&tlsserverth, NULL, tlsserverrd, (void *)client)) {
	    debug(DBG_ERR, "tlslistener: pthread_create failed");
	    SSL_free(client->peer.ssl);
	    shutdown(snew, SHUT_RDWR);
	    close(snew);
	    client->peer.ssl = NULL;
	    continue;
	}
	pthread_detach(tlsserverth);
    }
    return 0;
}

void tlsadd(char *value, char *cacertfile, char *cacertpath, char *certfile, char *certkeyfile, char *certkeypwd) {
    struct tls *new;
    SSL_CTX *ctx;
    int i;
    unsigned long error;
    
    if (!certfile || !certkeyfile)
	debugx(1, DBG_ERR, "TLSCertificateFile and TLSCertificateKeyFile must be specified in TLS context %s", value);

    if (!cacertfile && !cacertpath)
	debugx(1, DBG_ERR, "CA Certificate file or path need to be specified in TLS context %s", value);

    if (!ssl_locks) {
	ssl_locks = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	ssl_lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
	    ssl_lock_count[i] = 0;
	    pthread_mutex_init(&ssl_locks[i], NULL);
	}
	CRYPTO_set_id_callback(ssl_thread_id);
	CRYPTO_set_locking_callback(ssl_locking_callback);

	SSL_load_error_strings();
	SSL_library_init();

	while (!RAND_status()) {
	    time_t t = time(NULL);
	    pid_t pid = getpid();
	    RAND_seed((unsigned char *)&t, sizeof(time_t));
	    RAND_seed((unsigned char *)&pid, sizeof(pid));
	}
    }
    ctx = SSL_CTX_new(TLSv1_method());
    if (certkeypwd) {
	SSL_CTX_set_default_passwd_cb_userdata(ctx, certkeypwd);
	SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    }
    if (!SSL_CTX_use_certificate_chain_file(ctx, certfile) ||
	!SSL_CTX_use_PrivateKey_file(ctx, certkeyfile, SSL_FILETYPE_PEM) ||
	!SSL_CTX_check_private_key(ctx) ||
	!SSL_CTX_load_verify_locations(ctx, cacertfile, cacertpath)) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
	debugx(1, DBG_ERR, "Error initialising SSL/TLS in TLS context %s", value);
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
    SSL_CTX_set_verify_depth(ctx, MAX_CERT_DEPTH + 1);
    
    tls_count++;
    tlsconfs = realloc(tlsconfs, tls_count * sizeof(struct tls));
    if (!tlsconfs)
	debugx(1, DBG_ERR, "malloc failed");
    new = tlsconfs + tls_count - 1;
    memset(new, 0, sizeof(struct tls));
    new->name = stringcopy(value, 0);
    if (!new->name)
	debugx(1, DBG_ERR, "malloc failed");
    new->ctx = ctx;
    new->count = 0;
    debug(DBG_DBG, "tlsadd: added TLS context %s", value);
}

void tlsfree() {
    int i;
    for (i = 0; i < tls_count; i++) {
	free(tlsconfs[i].name);
	if (!tlsconfs[i].count)
	    SSL_CTX_free(tlsconfs[i].ctx);
    }
    tls_count = 0;
    free(tlsconfs);
    tlsconfs = NULL;
}

SSL_CTX *tlsgetctx(char *alt1, char *alt2) {
    int i, c1 = -1, c2 = -1;
    for (i = 0; i < tls_count; i++) {
	if (!strcasecmp(tlsconfs[i].name, alt1)) {
	    c1 = i;
	    break;
	}
	if (c2 == -1 && alt2 && !strcasecmp(tlsconfs[i].name, alt2))
	    c2 = i;
    }

    i = (c1 == -1 ? c2 : c1);
    if (i == -1)
	return NULL;
    tlsconfs[i].count++;
    return tlsconfs[i].ctx;
}

void addrealm(char *value, char *server, char *message) {
    int i, n;
    struct realm *realm;
    char *s, *regex = NULL;

    if (server) {
	for (i = 0; i < server_count; i++)
	    if (!strcasecmp(server, servers[i].peer.host))
		break;
	if (i == server_count)
	    debugx(1, DBG_ERR, "addrealm failed, no server %s", server);
    }
    
    if (*value == '/') {
	/* regexp, remove optional trailing / if present */
	if (value[strlen(value) - 1] == '/')
	    value[strlen(value) - 1] = '\0';
    } else {
	/* not a regexp, let us make it one */
	if (*value == '*' && !value[1])
	    regex = stringcopy(".*", 0);
	else {
	    for (n = 0, s = value; *s;)
		if (*s++ == '.')
		    n++;
	    regex = malloc(strlen(value) + n + 3);
	    if (regex) {
		regex[0] = '@';
		for (n = 1, s = value; *s; s++) {
		    if (*s == '.')
			regex[n++] = '\\';
		    regex[n++] = *s;
		}
		regex[n++] = '$';
		regex[n] = '\0';
	    }
	}
	if (!regex)
	    debugx(1, DBG_ERR, "malloc failed");
	debug(DBG_DBG, "addrealm: constructed regexp %s from %s", regex, value);
    }

    realm_count++;
    realms = realloc(realms, realm_count * sizeof(struct realm));
    if (!realms)
	debugx(1, DBG_ERR, "malloc failed");
    realm = realms + realm_count - 1;
    memset(realm, 0, sizeof(struct realm));
    realm->name = stringcopy(value, 0);
    if (!realm->name)
	debugx(1, DBG_ERR, "malloc failed");
    if (message && strlen(message) > 253)
	debugx(1, DBG_ERR, "ReplyMessage can be at most 253 bytes");
    realm->message = message;
    if (server)
	realm->serverno = i;
    if (regcomp(&realm->regex, regex ? regex : value + 1, REG_ICASE | REG_NOSUB))
	debugx(1, DBG_ERR, "addrealm: failed to compile regular expression %s", regex ? regex : value + 1);
    if (regex)
	free(regex);
    debug(DBG_DBG, "addrealm: added realm %s for server %s", value, server);
}

char *parsehostport(char *s, struct peer *peer) {
    char *p, *field;
    int ipv6 = 0;

    p = s;
    /* allow literal addresses and port, e.g. [2001:db8::1]:1812 */
    if (*p == '[') {
	p++;
	field = p;
	for (; *p && *p != ']' && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	if (*p != ']')
	    debugx(1, DBG_ERR, "no ] matching initial [");
	ipv6 = 1;
    } else {
	field = p;
	for (; *p && *p != ':' && *p != ' ' && *p != '\t' && *p != '\n'; p++);
    }
    if (field == p)
	debugx(1, DBG_ERR, "missing host/address");

    peer->host = stringcopy(field, p - field);
    if (ipv6) {
	p++;
	if (*p && *p != ':' && *p != ' ' && *p != '\t' && *p != '\n')
	    debugx(1, DBG_ERR, "unexpected character after ]");
    }
    if (*p == ':') {
	    /* port number or service name is specified */;
	    field = ++p;
	    for (; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	    if (field == p)
		debugx(1, DBG_ERR, "syntax error, : but no following port");
	    peer->port = stringcopy(field, p - field);
    } else
	peer->port = stringcopy(peer->type == 'U' ? DEFAULT_UDP_PORT : DEFAULT_TLS_PORT, 0);
    return p;
}

FILE *openconfigfile(const char *filename) {
    FILE *f;
    char pathname[100], *base = NULL;
    
    f = fopen(filename, "r");
    if (f) {
	debug(DBG_DBG, "reading config file %s", filename);
	return f;
    }

    if (strlen(filename) + 1 <= sizeof(pathname)) {
	/* basename() might modify the string */
	strcpy(pathname, filename);
	base = basename(pathname);
	f = fopen(base, "r");
    }

    if (!f)
	debugx(1, DBG_ERR, "could not read config file %s nor %s\n%s", filename, base, strerror(errno));
    
    debug(DBG_DBG, "reading config file %s", base);
    return f;
}

struct peer *server_create(char type) {
    struct peer *server;
    char *conf;

    server = malloc(sizeof(struct peer));
    if (!server)
	debugx(1, DBG_ERR, "malloc failed");
    memset(server, 0, sizeof(struct peer));
    server->type = type;
    conf = (type == 'T' ? options.listentcp : options.listenudp);
    if (conf) {
	parsehostport(conf, server);
	if (!strcmp(server->host, "*")) {
	    free(server->host);
	    server->host = NULL;
	}
    } else
	server->port = stringcopy(type == 'T' ? DEFAULT_TLS_PORT : DEFAULT_UDP_PORT, 0);
    if (!resolvepeer(server, AI_PASSIVE))
	debugx(1, DBG_ERR, "failed to resolve host %s port %s, exiting", server->host, server->port);
    return server;
}

/* returns NULL on error, where to continue parsing if token and ok. E.g. "" will return token with empty string */
char *strtokenquote(char *s, char **token, char *del, char *quote, char *comment) {
    char *t = s, *q, *r;

    if (!t || !token || !del)
	return NULL;
    while (*t && strchr(del, *t))
	t++;
    if (!*t || (comment && strchr(comment, *t))) {
	*token = NULL;
	return t + 1; /* needs to be non-NULL, but value doesn't matter */
    }
    if (quote && (q = strchr(quote, *t))) {
	t++;
	r = t;
	while (*t && *t != *q)
	    t++;
	if (!*t || (t[1] && !strchr(del, t[1])))
	    return NULL;
	*t = '\0';
	*token = r;
	return t + 1;
    }
    *token = t;
    t++;
    while (*t && !strchr(del, *t))
	t++;
    *t = '\0';
    return t + 1;
}

/* Parses config with following syntax:
 * One of these:
 * option-name value
 * option-name = value
 * Or:
 * option-name value {
 *     option-name [=] value
 *     ...
 * }
 */
void getgeneralconfig(FILE *f, char *block, ...) {
    va_list ap;
    char line[1024];
    /* initialise lots of stuff to avoid stupid compiler warnings */
    char *tokens[3], *s, *opt = NULL, *val = NULL, *word, *optval, **str = NULL;
    int type = 0, tcount, conftype = 0;
    void (*cbk)(FILE *, char *, char *, char *) = NULL;
	
    while (fgets(line, 1024, f)) {
	s = line;
	for (tcount = 0; tcount < 3; tcount++) {
	    s = strtokenquote(s, &tokens[tcount], " \t\r\n", "\"'", tcount ? NULL : "#");
	    if (!s)
		debugx(1, DBG_ERR, "Syntax error in line starting with: %s", line);
	    if (!tokens[tcount])
		break;
	}
	if (!tcount || **tokens == '#')
	    continue;

	if (**tokens == '}') {
	    if (block)
		return;
	    debugx(1, DBG_ERR, "configuration error, found } with no matching {");
	}
	    
	switch (tcount) {
	case 2:
	    opt = tokens[0];
	    val = tokens[1];
	    conftype = CONF_STR;
	    break;
	case 3:
	    if (tokens[1][0] == '=' && tokens[1][1] == '\0') {
		opt = tokens[0];
		val = tokens[2];
		conftype = CONF_STR;
		break;
	    }
	    if (tokens[2][0] == '{' && tokens[2][1] == '\0') {
		opt = tokens[0];
		val = tokens[1];
		conftype = CONF_CBK;
		break;
	    }
	    /* fall through */
	default:
	    if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, line starting with %s", block, tokens[0]);
	    debugx(1, DBG_ERR, "configuration error, syntax error in line starting with %s", tokens[0]);
	}

	if (!*val)
	    debugx(1, DBG_ERR, "configuration error, option %s needs a non-empty value", opt);
	
	va_start(ap, block);
	while ((word = va_arg(ap, char *))) {
	    type = va_arg(ap, int);
	    switch (type) {
	    case CONF_STR:
		str = va_arg(ap, char **);
		if (!str)
		    debugx(1, DBG_ERR, "getgeneralconfig: internal parameter error");
		break;
	    case CONF_CBK:
		cbk = va_arg(ap, void (*)(FILE *, char *, char *, char *));
		break;
	    default:
		debugx(1, DBG_ERR, "getgeneralconfig: internal parameter error");
	    }
	    if (!strcasecmp(opt, word))
		break;
	}
	va_end(ap);
	
	if (!word) {
	    if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, unknown option %s", block, opt);
	    debugx(1, DBG_ERR, "configuration error, unknown option %s", opt);
	}

	if (type != conftype) {
	    if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, wrong syntax for option %s", block, opt);
	    debugx(1, DBG_ERR, "configuration error, wrong syntax for option %s", opt);
	}
	
	switch (type) {
	case CONF_STR:
	    if (block)
		debug(DBG_DBG, "getgeneralconfig: block %s: %s = %s", block, opt, val);
	    else 
		debug(DBG_DBG, "getgeneralconfig: %s = %s", opt, val);
	    if (*str)
		debugx(1, DBG_ERR, "configuration error, option %s already set to %s", opt, *str);
	    *str = stringcopy(val, 0);
	    break;
	case CONF_CBK:
	    optval = malloc(strlen(opt) + strlen(val) + 2);
	    if (!optval)
		debugx(1, DBG_ERR, "malloc failed");
	    sprintf(optval, "%s %s", opt, val);
	    cbk(f, optval, opt, val);
	    free(optval);
	    break;
	default:
	    debugx(1, DBG_ERR, "getgeneralconfig: internal parameter error");
	}
    }
}

int addmatchcertattr(struct peer *conf, char *matchcertattr) {
    char *v;
    
    v = matchcertattr + 20;
    if (strncasecmp(matchcertattr, "SubjectAltName:URI:/", 20) || !*v)
        return 0;
    /* regexp, remove optional trailing / if present */
    if (v[strlen(v) - 1] == '/')
        v[strlen(v) - 1] = '\0';
    if (!*v)
        return 0;

    conf->certuriregex = malloc(sizeof(regex_t));
    if (!conf->certuriregex) {
        debug(DBG_ERR, "malloc failed");
        return 0;
    }
    if (regcomp(conf->certuriregex, v, REG_ICASE | REG_NOSUB)) {
        free(conf->certuriregex);
        conf->certuriregex = NULL;
        debug(DBG_ERR, "failed to compile regular expression %s", v);
        return 0;
    }
    return 1;
}

void confclsrv_cb(FILE *f, char *block, char *opt, char *val) {
    char *type = NULL, *secret = NULL, *port = NULL, *tls = NULL, *matchcertattr = NULL, *statusserver = NULL;
    struct client *client = NULL;
    struct server *server = NULL;
    struct peer *peer;
    
    debug(DBG_DBG, "confclsrv_cb called for %s", block);
    
    if (!strcasecmp(opt, "client")) {
	getgeneralconfig(f, block,
			 "type", CONF_STR, &type,
			 "secret", CONF_STR, &secret,
			 "tls", CONF_STR, &tls,
			 "matchcertificateattribute", CONF_STR, &matchcertattr,
			 NULL
			 );
	client_count++;
	clients = realloc(clients, client_count * sizeof(struct client));
	if (!clients)
	    debugx(1, DBG_ERR, "malloc failed");
	client = clients + client_count - 1;
	memset(client, 0, sizeof(struct client));
	peer = &client->peer;
    } else {
	getgeneralconfig(f, block,
			 "type", CONF_STR, &type,
			 "secret", CONF_STR, &secret,
			 "port", CONF_STR, &port,
			 "tls", CONF_STR, &tls,
			 "matchcertificateattribute", CONF_STR, &matchcertattr,
			 "StatusServer", CONF_STR, &statusserver,
			 NULL
			 );
	server_count++;
	servers = realloc(servers, server_count * sizeof(struct server));
	if (!servers)
	    debugx(1, DBG_ERR, "malloc failed");
	server = servers + server_count - 1;
	memset(server, 0, sizeof(struct server));
	peer = &server->peer;
	peer->port = port;
	if (statusserver) {
	    if (!strcasecmp(statusserver, "on"))
		server->statusserver = 1;
	    else if (strcasecmp(statusserver, "off"))
		debugx(1, DBG_ERR, "error in block %s, StatusServer is %s, must be on or off", block, statusserver);
	    free(statusserver);
	}
    }
    
    peer->host = stringcopy(val, 0);
    
    if (type && !strcasecmp(type, "udp")) {
	peer->type = 'U';
	if (client)
	    client_udp_count++;
	else {
	    server_udp_count++;
	    if (!port)
		peer->port = stringcopy(DEFAULT_UDP_PORT, 0);
	}
    } else if (type && !strcasecmp(type, "tls")) {
	if (client) {
	    peer->ssl_ctx = tls ? tlsgetctx(tls, NULL) : tlsgetctx("defaultclient", "default");
	    client_tls_count++;
	} else {
	    peer->ssl_ctx = tls ? tlsgetctx(tls, NULL) : tlsgetctx("defaultserver", "default");
	    server_tls_count++;
	    if (!port)
		peer->port = stringcopy(DEFAULT_TLS_PORT, 0);
	}
	if (!peer->ssl_ctx)
	    debugx(1, DBG_ERR, "error in block %s, no tls context defined", block);
	if (matchcertattr && !addmatchcertattr(peer, matchcertattr))
	    debugx(1, DBG_ERR, "error in block %s, invalid MatchCertificateAttributeValue", block);
	peer->type = 'T';
    } else
	debugx(1, DBG_ERR, "error in block %s, type must be set to UDP or TLS", block);
    free(type);
    if (tls)
	free(tls);
    if (matchcertattr)
	free(matchcertattr);
    
    if (!resolvepeer(peer, 0))
	debugx(1, DBG_ERR, "failed to resolve host %s port %s, exiting", peer->host, peer->port);
    
    if (!secret) {
	if (peer->type == 'U')
	    debugx(1, DBG_ERR, "error in block %s, secret must be specified for UDP", block);
	peer->secret = stringcopy(DEFAULT_TLS_SECRET, 0);
    } else {
	peer->secret = secret;
    }

    if (client) {
	if (peer->type == 'U')
	    client->replyq = &udp_server_replyq;
	else {
	    client->replyq = malloc(sizeof(struct replyq));
	    if (!client->replyq)
		debugx(1, DBG_ERR, "malloc failed");
	    client->replyq->replies = calloc(MAX_REQUESTS, sizeof(struct reply));
	    if (!client->replyq->replies)
		debugx(1, DBG_ERR, "malloc failed");
	    client->replyq->size = MAX_REQUESTS;
	    client->replyq->count = 0;
	    pthread_mutex_init(&client->replyq->count_mutex, NULL);
	    pthread_cond_init(&client->replyq->count_cond, NULL);
	}
    } else {
	pthread_mutex_init(&server->lock, NULL);
	server->sock = -1;
	server->requests = calloc(MAX_REQUESTS, sizeof(struct request));
	if (!server->requests)
	    debugx(1, DBG_ERR, "malloc failed");
	server->newrq = 0;
	pthread_mutex_init(&server->newrq_mutex, NULL);
	pthread_cond_init(&server->newrq_cond, NULL);
    }
}

void confrealm_cb(FILE *f, char *block, char *opt, char *val) {
    char *server = NULL, *msg = NULL;
    
    debug(DBG_DBG, "confrealm_cb called for %s", block);
    
    getgeneralconfig(f, block,
		     "server", CONF_STR, &server,
		     "ReplyMessage", CONF_STR, &msg,
		     NULL
		     );

    addrealm(val, server, msg);
    free(server);
}

void conftls_cb(FILE *f, char *block, char *opt, char *val) {
    char *cacertfile = NULL, *cacertpath = NULL, *certfile = NULL, *certkeyfile = NULL, *certkeypwd = NULL;
    
    debug(DBG_DBG, "conftls_cb called for %s", block);
    
    getgeneralconfig(f, block,
		     "CACertificateFile", CONF_STR, &cacertfile,
		     "CACertificatePath", CONF_STR, &cacertpath,
		     "CertificateFile", CONF_STR, &certfile,
		     "CertificateKeyFile", CONF_STR, &certkeyfile,
		     "CertificateKeyPassword", CONF_STR, &certkeypwd,
		     NULL
		     );
    
    tlsadd(val, cacertfile, cacertpath, certfile, certkeyfile, certkeypwd);
    free(cacertfile);
    free(cacertpath);
    free(certfile);
    free(certkeyfile);
    free(certkeypwd);
}

void getmainconfig(const char *configfile) {
    FILE *f;
    char *loglevel = NULL;

    f = openconfigfile(configfile);
    memset(&options, 0, sizeof(options));

    getgeneralconfig(f, NULL,
		     "ListenUDP", CONF_STR, &options.listenudp,
		     "ListenTCP", CONF_STR, &options.listentcp,
		     "LogLevel", CONF_STR, &loglevel,
		     "LogDestination", CONF_STR, &options.logdestination,
		     "Client", CONF_CBK, confclsrv_cb,
		     "Server", CONF_CBK, confclsrv_cb,
		     "Realm", CONF_CBK, confrealm_cb,
		     "TLS", CONF_CBK, conftls_cb,
		     NULL
		     );
    fclose(f);
    tlsfree();
    
    if (loglevel) {
	if (strlen(loglevel) != 1 || *loglevel < '1' || *loglevel > '4')
	    debugx(1, DBG_ERR, "error in %s, value of option LogLevel is %s, must be 1, 2, 3 or 4", configfile, loglevel);
	options.loglevel = *loglevel - '0';
	free(loglevel);
    }

    if (client_udp_count) {
	udp_server_replyq.replies = malloc(client_udp_count * MAX_REQUESTS * sizeof(struct reply));
	if (!udp_server_replyq.replies)
	    debugx(1, DBG_ERR, "malloc failed");
	udp_server_replyq.size = client_udp_count * MAX_REQUESTS;
	udp_server_replyq.count = 0;
	pthread_mutex_init(&udp_server_replyq.count_mutex, NULL);
	pthread_cond_init(&udp_server_replyq.count_cond, NULL);
    }    
}

void getargs(int argc, char **argv, uint8_t *foreground, uint8_t *loglevel, char **configfile) {
    int c;

    while ((c = getopt(argc, argv, "c:d:fv")) != -1) {
	switch (c) {
	case 'c':
	    *configfile = optarg;
	    break;
	case 'd':
	    if (strlen(optarg) != 1 || *optarg < '1' || *optarg > '4')
		debugx(1, DBG_ERR, "Debug level must be 1, 2, 3 or 4, not %s", optarg);
	    *loglevel = *optarg - '0';
	    break;
	case 'f':
	    *foreground = 1;
	    break;
	case 'v':
		debugx(0, DBG_ERR, "radsecproxy 1.0p1");
	default:
	    goto usage;
	}
    }
    if (!(argc - optind))
	return;

 usage:
    debug(DBG_ERR, "Usage:\n%s [ -c configfile ] [ -d debuglevel ] [ -f ] [ -v ]", argv[0]);
    exit(1);
}

int main(int argc, char **argv) {
    pthread_t udpserverth;
    int i;
    uint8_t foreground = 0, loglevel = 0;
    char *configfile = NULL;
    
    debug_init("radsecproxy");
    debug_set_level(DEBUG_LEVEL);
    getargs(argc, argv, &foreground, &loglevel, &configfile);
    if (loglevel)
	debug_set_level(loglevel);
    getmainconfig(configfile ? configfile : CONFIG_MAIN);
    if (loglevel)
	options.loglevel = loglevel;
    else if (options.loglevel)
	debug_set_level(options.loglevel);
    if (foreground)
	options.logdestination = NULL;
    else {
	if (!options.logdestination)
	    options.logdestination = "x-syslog:///";
	debug_set_destination(options.logdestination);
    }

    if (!server_count)
	debugx(1, DBG_ERR, "No servers configured, nothing to do, exiting");
    if (!client_count)
	debugx(1, DBG_ERR, "No clients configured, nothing to do, exiting");
    if (!realm_count)
	debugx(1, DBG_ERR, "No realms configured, nothing to do, exiting");

    if (!foreground && (daemon(0, 0) < 0))
	debugx(1, DBG_ERR, "daemon() failed: %s", strerror(errno));
	
    debug(DBG_INFO, "radsecproxy 1.0p1 starting");

    if (client_udp_count) {
	udp_server_listen = server_create('U');
	if (pthread_create(&udpserverth, NULL, udpserverrd, NULL))
	    debugx(1, DBG_ERR, "pthread_create failed");
    }
    
    for (i = 0; i < server_count; i++)
	if (pthread_create(&servers[i].clientth, NULL, clientwr, (void *)&servers[i]))
	    debugx(1, DBG_ERR, "pthread_create failed");

    if (client_tls_count) {
	tcp_server_listen = server_create('T');
	return tlslistener();
    }
    
    /* just hang around doing nothing, anything to do here? */
    for (;;)
	sleep(1000);
}
