/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
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

/* Bugs:
 * TCP accounting not yet supported
 * We are not removing client requests from dynamic servers, see removeclientrqs()
 */

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
#include "udp.h"
#include "tcp.h"
#include "tls.h"
#include "dtls.h"

static struct options options;
static struct list *clconfs, *srvconfs;
struct list *realms;
struct hash *tlsconfs, *rewriteconfs;

static struct addrinfo *srcprotores[4] = { NULL, NULL, NULL, NULL };

static pthread_mutex_t *ssl_locks = NULL;
static long *ssl_lock_count;
extern int optind;
extern char *optarg;

/* minimum required declarations to avoid reordering code */
void adddynamicrealmserver(struct realm *realm, struct clsrvconf *conf, char *id);
int dynamicconfig(struct server *server);
int confserver_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
void freerealm(struct realm *realm);
void freeclsrvconf(struct clsrvconf *conf);
void freerqdata(struct request *rq);

static const struct protodefs protodefs[] = {
    {   "udp", /* UDP, assuming RAD_UDP defined as 0 */
	NULL, /* secretdefault */
	SOCK_DGRAM, /* socktype */
	"1812", /* portdefault */
	REQUEST_RETRY_COUNT, /* retrycountdefault */
	10, /* retrycountmax */
	REQUEST_RETRY_INTERVAL, /* retryintervaldefault */
	60, /* retryintervalmax */
	udpserverrd, /* listener */
	&options.sourceudp, /* srcaddrport */
	NULL, /* connecter */
	NULL, /* clientconnreader */
	clientradputudp, /* clientradput */
	addclientudp, /* addclient */
	addserverextraudp, /* addserverextra */
	initextraudp /* initextra */
    },
    {   "tls", /* TLS, assuming RAD_TLS defined as 1 */
	"mysecret", /* secretdefault */
	SOCK_STREAM, /* socktype */
	"2083", /* portdefault */
	0, /* retrycountdefault */
	0, /* retrycountmax */
	REQUEST_RETRY_INTERVAL * REQUEST_RETRY_COUNT, /* retryintervaldefault */
	60, /* retryintervalmax */
	tlslistener, /* listener */
	&options.sourcetls, /* srcaddrport */
	tlsconnect, /* connecter */
	tlsclientrd, /* clientconnreader */
	clientradputtls, /* clientradput */
	NULL, /* addclient */
	NULL, /* addserverextra */
	NULL /* initextra */
    },
    {   "tcp", /* TCP, assuming RAD_TCP defined as 2 */
	NULL, /* secretdefault */
	SOCK_STREAM, /* socktype */
	"1812", /* portdefault */
	0, /* retrycountdefault */
	0, /* retrycountmax */
	REQUEST_RETRY_INTERVAL * REQUEST_RETRY_COUNT, /* retryintervaldefault */
	60, /* retryintervalmax */
	tcplistener, /* listener */
	&options.sourcetcp, /* srcaddrport */
	tcpconnect, /* connecter */
	tcpclientrd, /* clientconnreader */
	clientradputtcp, /* clientradput */
	NULL, /* addclient */
	NULL, /* addserverextra */
	NULL /* initextra */
    },
    {   "dtls", /* DTLS, assuming RAD_DTLS defined as 3 */
	"mysecret", /* secretdefault */
	SOCK_DGRAM, /* socktype */
	"2083", /* portdefault */
	REQUEST_RETRY_COUNT, /* retrycountdefault */
	10, /* retrycountmax */
	REQUEST_RETRY_INTERVAL, /* retryintervaldefault */
	60, /* retryintervalmax */
	udpdtlsserverrd, /* listener */
	&options.sourcedtls, /* srcaddrport */
	dtlsconnect, /* connecter */
	dtlsclientrd, /* clientconnreader */
	clientradputdtls, /* clientradput */
	NULL, /* addclient */
	addserverextradtls, /* addserverextra */
	initextradtls /* initextra */
    },
    {   NULL
    }
};

uint8_t protoname2int(const char *name) {
    int i;

    for (i = 0; protodefs[i].name && strcasecmp(protodefs[i].name, name); i++);
    return i;
}
    
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

struct addrinfo *getsrcprotores(uint8_t type) {
    return srcprotores[type];
}

int resolvepeer(struct clsrvconf *conf, int ai_flags) {
    struct addrinfo hints, *addrinfo, *res;
    char *slash, *s;
    int plen = 0;

    slash = conf->host ? strchr(conf->host, '/') : NULL;
    if (slash) {
	s = slash + 1;
	if (!*s) {
	    debug(DBG_WARN, "resolvepeer: prefix length must be specified after the / in %s", conf->host);
	    return 0;
	}
	for (; *s; s++)
	    if (*s < '0' || *s > '9') {
		debug(DBG_WARN, "resolvepeer: %s in %s is not a valid prefix length", slash + 1, conf->host);
		return 0;
	    }
	plen = atoi(slash + 1);
	if (plen < 0 || plen > 128) {
	    debug(DBG_WARN, "resolvepeer: %s in %s is not a valid prefix length", slash + 1, conf->host);
	    return 0;
	}
	*slash = '\0';
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = conf->pdef->socktype;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = ai_flags;
    if (!conf->host && !conf->port) {
	/* getaddrinfo() doesn't like host and port to be NULL */
	if (getaddrinfo(conf->host, conf->pdef->portdefault, &hints, &addrinfo)) {
	    debug(DBG_WARN, "resolvepeer: can't resolve (null) port (null)");
	    return 0;
	}
	for (res = addrinfo; res; res = res->ai_next) {
	    switch (res->ai_family) {
	    case AF_INET:
		((struct sockaddr_in *)res->ai_addr)->sin_port = 0;
		break;
	    case AF_INET6:
		((struct sockaddr_in6 *)res->ai_addr)->sin6_port = 0;
		break;
	    }
	}
    } else {
	if (slash)
	    hints.ai_flags |= AI_NUMERICHOST;
	if (getaddrinfo(conf->host, conf->port, &hints, &addrinfo)) {
	    debug(DBG_WARN, "resolvepeer: can't resolve %s port %s", conf->host ? conf->host : "(null)", conf->port ? conf->port : "(null)");
	    return 0;
	}
	if (slash) {
	    *slash = '/';
	    switch (addrinfo->ai_family) {
	    case AF_INET:
		if (plen > 32) {
		    debug(DBG_WARN, "resolvepeer: prefix length must be <= 32 in %s", conf->host);
		    freeaddrinfo(addrinfo);
		    return 0;
		}
		break;
	    case AF_INET6:
		break;
	    default:
		debug(DBG_WARN, "resolvepeer: prefix must be IPv4 or IPv6 in %s", conf->host);
		freeaddrinfo(addrinfo);
		return 0;
	    }
	    conf->prefixlen = plen;
	} else
	    conf->prefixlen = 255;
    }
    if (conf->addrinfo)
	freeaddrinfo(conf->addrinfo);
    conf->addrinfo = addrinfo;
    return 1;
}	  

char *parsehostport(char *s, struct clsrvconf *conf, char *default_port) {
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

    conf->host = stringcopy(field, p - field);
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
	    conf->port = stringcopy(field, p - field);
    } else
	conf->port = default_port ? stringcopy(default_port, 0) : NULL;
    return p;
}

struct clsrvconf *resolve_hostport(uint8_t type, char *lconf, char *default_port) {
    struct clsrvconf *conf;

    conf = malloc(sizeof(struct clsrvconf));
    if (!conf)
	debugx(1, DBG_ERR, "malloc failed");
    memset(conf, 0, sizeof(struct clsrvconf));
    conf->type = type;
    conf->pdef = &protodefs[conf->type];
    if (lconf) {
	parsehostport(lconf, conf, default_port);
	if (!strcmp(conf->host, "*")) {
	    free(conf->host);
	    conf->host = NULL;
	}
    } else
	conf->port = default_port ? stringcopy(default_port, 0) : NULL;
    if (!resolvepeer(conf, AI_PASSIVE))
	debugx(1, DBG_ERR, "failed to resolve host %s port %s, exiting", conf->host ? conf->host : "(null)", conf->port ? conf->port : "(null)");
    return conf;
}

void freeclsrvres(struct clsrvconf *res) {
    free(res->host);
    free(res->port);
    if (res->addrinfo)
	freeaddrinfo(res->addrinfo);
    free(res);
}

int bindtoaddr(struct addrinfo *addrinfo, int family, int reuse, int v6only) {
    int s, on = 1;
    struct addrinfo *res;

    for (res = addrinfo; res; res = res->ai_next) {
	if (family != AF_UNSPEC && family != res->ai_family)
	    continue;
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0) {
	    debug(DBG_WARN, "bindtoaddr: socket failed");
	    continue;
	}
	if (reuse)
	    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef IPV6_V6ONLY
	if (v6only)
	    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
	if (!bind(s, res->ai_addr, res->ai_addrlen))
	    return s;
	debug(DBG_WARN, "bindtoaddr: bind failed");
	close(s);
    }
    return -1;
}
	
int connecttcp(struct addrinfo *addrinfo, struct addrinfo *src) {
    int s;
    struct addrinfo *res;

    s = -1;
    for (res = addrinfo; res; res = res->ai_next) {
	s = bindtoaddr(src, res->ai_family, 1, 1);
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

/* returns 1 if the len first bits are equal, else 0 */
int prefixmatch(void *a1, void *a2, uint8_t len) {
    static uint8_t mask[] = { 0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
    int r, l = len / 8;
    if (l && memcmp(a1, a2, l))
	return 0;
    r = len % 8;
    if (!r)
	return 1;
    return (((uint8_t *)a1)[l] & mask[r]) == (((uint8_t *)a2)[l] & mask[r]);
}

/* returns next config with matching address, or NULL */
struct clsrvconf *find_conf(uint8_t type, struct sockaddr *addr, struct list *confs, struct list_node **cur) {
    struct sockaddr_in6 *sa6 = NULL;
    struct in_addr *a4 = NULL;
    struct addrinfo *res;
    struct list_node *entry;
    struct clsrvconf *conf;
    
    if (addr->sa_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
            a4 = (struct in_addr *)&sa6->sin6_addr.s6_addr[12];
	    sa6 = NULL;
	}
    } else
	a4 = &((struct sockaddr_in *)addr)->sin_addr;

    for (entry = (cur && *cur ? list_next(*cur) : list_first(confs)); entry; entry = list_next(entry)) {
	conf = (struct clsrvconf *)entry->data;
	if (conf->type == type) {
	    if (conf->prefixlen == 255) {
		for (res = conf->addrinfo; res; res = res->ai_next)
		    if ((a4 && res->ai_family == AF_INET &&
			 !memcmp(a4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4)) ||
			(sa6 && res->ai_family == AF_INET6 &&
			 !memcmp(&sa6->sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, 16))) {
			if (cur)
			    *cur = entry;
			return conf;
		    }
	    } else {
		res = conf->addrinfo;
		if (res &&
		    ((a4 && res->ai_family == AF_INET &&
		      prefixmatch(a4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, conf->prefixlen)) ||
		     (sa6 && res->ai_family == AF_INET6 &&
		      prefixmatch(&sa6->sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, conf->prefixlen)))) {
		    if (cur)
			*cur = entry;
		    return conf;
		}
	    }
	}
    }    
    return NULL;
}

struct clsrvconf *find_clconf(uint8_t type, struct sockaddr *addr, struct list_node **cur) {
    return find_conf(type, addr, clconfs, cur);
}

struct clsrvconf *find_srvconf(uint8_t type, struct sockaddr *addr, struct list_node **cur) {
    return find_conf(type, addr, srvconfs, cur);
}

/* returns next config of given type, or NULL */
struct clsrvconf *find_clconf_type(uint8_t type, struct list_node **cur) {
    struct list_node *entry;
    struct clsrvconf *conf;
    
    for (entry = (cur && *cur ? list_next(*cur) : list_first(clconfs)); entry; entry = list_next(entry)) {
	conf = (struct clsrvconf *)entry->data;
	if (conf->type == type) {
	    if (cur)
		*cur = entry;
	    return conf;
	}
    }    
    return NULL;
}

struct queue *newqueue() {
    struct queue *q;
    
    q = malloc(sizeof(struct queue));
    if (!q)
	debugx(1, DBG_ERR, "malloc failed");
    q->entries = list_create();
    if (!q->entries)
	debugx(1, DBG_ERR, "malloc failed");
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
    return q;
}

void removequeue(struct queue *q) {
    struct list_node *entry;

    if (!q)
	return;
    pthread_mutex_lock(&q->mutex);
    for (entry = list_first(q->entries); entry; entry = list_next(entry))
	free(((struct reply *)entry)->buf);
    list_destroy(q->entries);
    pthread_cond_destroy(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    free(q);
}

void freebios(struct queue *q) {
    BIO *bio;
    
    pthread_mutex_lock(&q->mutex);
    while ((bio = (BIO *)list_shift(q->entries)))
	BIO_free(bio);
    pthread_mutex_unlock(&q->mutex);
    removequeue(q);
}

struct client *addclient(struct clsrvconf *conf) {
    struct client *new = malloc(sizeof(struct client));
    
    if (!new) {
	debug(DBG_ERR, "malloc failed");
	return NULL;
    }
    if (!conf->clients) {
	conf->clients = list_create();
	if (!conf->clients) {
	    debug(DBG_ERR, "malloc failed");
	    return NULL;
	}
    }
    
    memset(new, 0, sizeof(struct client));
    new->conf = conf;
    if (conf->pdef->addclient)
	conf->pdef->addclient(new);
    else
	new->replyq = newqueue();
    list_push(conf->clients, new);
    return new;
}

void removeclient(struct client *client) {
    if (!client || !client->conf->clients)
	return;
    removequeue(client->replyq);
    list_removedata(client->conf->clients, client);
    free(client);
}

void removeclientrqs(struct client *client) {
    struct list_node *entry;
    struct server *server;
    struct request *rq;
    int i;
    
    for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	server = ((struct clsrvconf *)entry->data)->servers;
	if (!server)
	    continue;
	pthread_mutex_lock(&server->newrq_mutex);
	for (i = 0; i < MAX_REQUESTS; i++) {
	    rq = server->requests + i;
	    if (rq->from == client)
		rq->from = NULL;
	}
	pthread_mutex_unlock(&server->newrq_mutex);
    }
}

void freeserver(struct server *server, uint8_t destroymutex) {
    struct request *rq, *end;

    if (!server)
	return;

    if (server->requests) {
	rq = server->requests;
	for (end = rq + MAX_REQUESTS; rq < end; rq++)
	    freerqdata(rq);
	free(server->requests);
    }
    if (server->rbios)
	freebios(server->rbios);
    free(server->dynamiclookuparg);
    if (server->ssl)
	SSL_free(server->ssl);
    if (destroymutex) {
	pthread_mutex_destroy(&server->lock);
	pthread_cond_destroy(&server->newrq_cond);
	pthread_mutex_destroy(&server->newrq_mutex);
    }
    free(server);
}

int addserver(struct clsrvconf *conf) {
    struct clsrvconf *res;
    uint8_t type;
    
    if (conf->servers) {
	debug(DBG_ERR, "addserver: currently works with just one server per conf");
	return 0;
    }
    conf->servers = malloc(sizeof(struct server));
    if (!conf->servers) {
	debug(DBG_ERR, "malloc failed");
	return 0;
    }
    memset(conf->servers, 0, sizeof(struct server));
    conf->servers->conf = conf;

    type = conf->type;
    if (type == RAD_DTLS)
	conf->servers->rbios = newqueue();
    
    if (!srcprotores[type]) {
	res = resolve_hostport(type, *conf->pdef->srcaddrport, NULL);
	srcprotores[type] = res->addrinfo;
	res->addrinfo = NULL;
	freeclsrvres(res);
    }

    conf->servers->sock = -1;
    if (conf->pdef->addserverextra)
	conf->pdef->addserverextra(conf);
    
    conf->servers->requests = calloc(MAX_REQUESTS, sizeof(struct request));
    if (!conf->servers->requests) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    if (pthread_mutex_init(&conf->servers->lock, NULL)) {
	debug(DBG_ERR, "mutex init failed");
	goto errexit;
    }
    conf->servers->newrq = 0;
    if (pthread_mutex_init(&conf->servers->newrq_mutex, NULL)) {
	debug(DBG_ERR, "mutex init failed");
	pthread_mutex_destroy(&conf->servers->lock);
	goto errexit;
    }
    if (pthread_cond_init(&conf->servers->newrq_cond, NULL)) {
	debug(DBG_ERR, "mutex init failed");
	pthread_mutex_destroy(&conf->servers->newrq_mutex);
	pthread_mutex_destroy(&conf->servers->lock);
	goto errexit;
    }

    return 1;
    
 errexit:
    freeserver(conf->servers, 0);
    conf->servers = NULL;
    return 0;
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

int cnregexp(X509 *cert, char *exact, regex_t *regex) {
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
    
int verifyconfcert(X509 *cert, struct clsrvconf *conf) {
    int r;
    uint8_t type = 0; /* 0 for DNS, AF_INET for IPv4, AF_INET6 for IPv6 */
    struct in6_addr addr;
    
    if (conf->certnamecheck && conf->prefixlen == 255) {
	if (inet_pton(AF_INET, conf->host, &addr))
	    type = AF_INET;
	else if (inet_pton(AF_INET6, conf->host, &addr))
	    type = AF_INET6;

	r = type ? subjectaltnameaddr(cert, type, &addr) : subjectaltnameregexp(cert, GEN_DNS, conf->host, NULL);
	if (r) {
	    if (r < 0) {
		debug(DBG_WARN, "verifyconfcert: No subjectaltname matching %s %s", type ? "address" : "host", conf->host);
		return 0;
	    }
	    debug(DBG_DBG, "verifyconfcert: Found subjectaltname matching %s %s", type ? "address" : "host", conf->host);
	} else {
	    if (!cnregexp(cert, conf->host, NULL)) {
		debug(DBG_WARN, "verifyconfcert: cn not matching host %s", conf->host);
		return 0;
	    }		
	    debug(DBG_DBG, "verifyconfcert: Found cn matching host %s", conf->host);
	}
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

void freerqdata(struct request *rq) {
    if (rq->origusername)
	free(rq->origusername);
    if (rq->buf)
	free(rq->buf);
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
	    debug(DBG_WARN, "sendrq: no room in queue, dropping request");
	    freerqdata(rq);
	    goto exit;
	}
    }
    
    rq->buf[1] = (char)i;

    attr = attrget(rq->buf + 20, RADLEN(rq->buf) - 20, RAD_Attr_Message_Authenticator);
    if (attr && !createmessageauth(rq->buf, ATTRVAL(attr), to->conf->secret)) {
	freerqdata(rq);
	goto exit;
    }
    
    if (*rq->buf == RAD_Accounting_Request) {
	if (!radsign(rq->buf, (unsigned char *)to->conf->secret)) {
	    debug(DBG_WARN, "sendrq: failed to sign Accounting-Request message");
	    freerqdata(rq);
	    goto exit;
	}
    }

    debug(DBG_DBG, "sendrq: inserting packet with id %d in queue for %s", i, to->conf->host);
    to->requests[i] = *rq;
    to->nextid = i + 1;

    if (!to->newrq) {
	to->newrq = 1;
	debug(DBG_DBG, "sendrq: signalling client writer");
	pthread_cond_signal(&to->newrq_cond);
    }
 exit:
    pthread_mutex_unlock(&to->newrq_mutex);
}

void sendreply(struct client *to, unsigned char *buf, struct sockaddr_storage *tosa, int toudpsock) {
    struct reply *reply;
    uint8_t first;
    
    if (!radsign(buf, (unsigned char *)to->conf->secret)) {
	free(buf);
	debug(DBG_WARN, "sendreply: failed to sign message");
	return;
    }

    reply = malloc(sizeof(struct reply));
    if (!reply) {
	free(buf);
	debug(DBG_ERR, "sendreply: malloc failed");
	return;
    }
    memset(reply, 0, sizeof(struct reply));
    reply->buf = buf;
    if (tosa)
	reply->tosa = *tosa;
    reply->toudpsock = toudpsock;
    
    pthread_mutex_lock(&to->replyq->mutex);

    first = list_first(to->replyq->entries) == NULL;
    
    if (!list_push(to->replyq->entries, reply)) {
	pthread_mutex_unlock(&to->replyq->mutex);
	free(reply);
	free(buf);
	debug(DBG_ERR, "sendreply: malloc failed");
	return;
    }
    
    if (first) {
	debug(DBG_DBG, "signalling server writer");
	pthread_cond_signal(&to->replyq->cond);
    }
    pthread_mutex_unlock(&to->replyq->mutex);
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

struct realm *id2realm(struct list *realmlist, char *id) {
    struct list_node *entry;
    struct realm *realm, *subrealm = NULL;

    /* need to do locking for subrealms and check subrealm timers */
    for (entry = list_first(realmlist); entry; entry = list_next(entry)) {
	realm = (struct realm *)entry->data;
	if (!regexec(&realm->regex, id, 0, NULL, 0)) {
	    pthread_mutex_lock(&realm->subrealms_mutex);
	    if (realm->subrealms)
		subrealm = id2realm(realm->subrealms, id);
	    pthread_mutex_unlock(&realm->subrealms_mutex);
	    return subrealm ? subrealm : realm;
	}
    }
    return NULL;
}

/* helper function, only used by removeserversubrealms() */
void _internal_removeserversubrealms(struct list *realmlist, struct clsrvconf *srv) {
    struct list_node *entry;
    struct realm *realm;
    
    for (entry = list_first(realmlist); entry;) {
	realm = (struct realm *)entry->data;
	entry = list_next(entry);
	if (realm->srvconfs) {
	    list_removedata(realm->srvconfs, srv);
	    if (!list_first(realm->srvconfs)) {
		list_destroy(realm->srvconfs);
		realm->srvconfs = NULL;
	    }
	}
	if (realm->accsrvconfs) {
	    list_removedata(realm->accsrvconfs, srv);
	    if (!list_first(realm->accsrvconfs)) {
		list_destroy(realm->accsrvconfs);
		realm->accsrvconfs = NULL;
	    }
	}

	/* remove subrealm if no servers */
	if (!realm->srvconfs && !realm->accsrvconfs) {
	    list_removedata(realmlist, realm);
	    freerealm(realm);
	}
    }
}

void removeserversubrealms(struct list *realmlist, struct clsrvconf *srv) {
    struct list_node *entry;
    struct realm *realm;
    
    for (entry = list_first(realmlist); entry; entry = list_next(entry)) {
	realm = (struct realm *)entry->data;
	pthread_mutex_lock(&realm->subrealms_mutex);
	if (realm->subrealms) {
	    _internal_removeserversubrealms(realm->subrealms, srv);
	    if (!list_first(realm->subrealms)) {
		list_destroy(realm->subrealms);
		realm->subrealms = NULL;
	    }
	}
	pthread_mutex_unlock(&realm->subrealms_mutex);
    }
}
			
int rqinqueue(struct server *to, struct client *from, uint8_t id, uint8_t code) {
    struct request *rq = to->requests, *end;
    
    pthread_mutex_lock(&to->newrq_mutex);
    for (end = rq + MAX_REQUESTS; rq < end; rq++)
	if (rq->buf && !rq->received && rq->origid == id && rq->from == from && *rq->buf == code)
	    break;
    pthread_mutex_unlock(&to->newrq_mutex);
    
    return rq < end;
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

int findvendorsubattr(uint32_t *attrs, uint32_t vendor, uint8_t subattr) {
    if (!attrs)
	return 0;
    
    for (; attrs[0]; attrs += 2)
	if (attrs[0] == vendor && attrs[1] == subattr)
	    return 1;
    return 0;
}

int dovendorrewrite(uint8_t *attrs, uint16_t length, uint32_t *removevendorattrs) {
    uint8_t alen, sublen, rmlen = 0;
    uint32_t vendor = *(uint32_t *)ATTRVAL(attrs);
    uint8_t *subattrs;
    
    if (!removevendorattrs)
	return 0;

    while (*removevendorattrs && *removevendorattrs != vendor)
	removevendorattrs += 2;
    if (!*removevendorattrs)
	return 0;
    
    alen = ATTRLEN(attrs);

    if (findvendorsubattr(removevendorattrs, vendor, -1)) {
	/* remove entire vendor attribute */
	memmove(attrs, attrs + alen, length - alen);
	return alen;
    }

    sublen = alen - 4;
    subattrs = ATTRVAL(attrs) + 4;
    
    if (!attrvalidate(subattrs, sublen)) {
	debug(DBG_WARN, "dovendorrewrite: vendor attribute validation failed, no rewrite");
	return 0;
    }

    length -= 6;
    while (sublen > 1) {
	alen = ATTRLEN(subattrs);
	sublen -= alen;
	length -= alen;
	if (findvendorsubattr(removevendorattrs, vendor, ATTRTYPE(subattrs))) {
	    memmove(subattrs, subattrs + alen, length);
	    rmlen += alen;
	} else
	    subattrs += alen;
    }

    ATTRLEN(attrs) -= rmlen;
    return rmlen;
}

void dorewrite(uint8_t *buf, struct rewrite *rewrite) {
    uint8_t *attrs, alen;
    uint16_t len, rmlen = 0;
    
    if (!rewrite || (!rewrite->removeattrs && !rewrite->removevendorattrs))
	return;

    len = RADLEN(buf) - 20;
    attrs = buf + 20;
    while (len > 1) {
	alen = ATTRLEN(attrs);
	len -= alen;
	if (rewrite->removeattrs && strchr((char *)rewrite->removeattrs, ATTRTYPE(attrs))) {
	    memmove(attrs, attrs + alen, len);
	    rmlen += alen;
	} else if (ATTRTYPE(attrs) == RAD_Attr_Vendor_Specific && rewrite->removevendorattrs)
	    rmlen += dovendorrewrite(attrs, len, rewrite->removevendorattrs);
	else
	    attrs += alen;
    }
    if (rmlen)
	((uint16_t *)buf)[1] = htons(RADLEN(buf) - rmlen);
}

/* returns a pointer to the resized attribute value */
uint8_t *resizeattr(uint8_t **buf, uint8_t newvallen, uint8_t type) {
    uint8_t *attrs, *attr, vallen;
    uint16_t len;
    unsigned char *new;
    
    len = RADLEN(*buf) - 20;
    attrs = *buf + 20;

    attr = attrget(attrs, len, type);
    if (!attr)
	return NULL;
    
    vallen = ATTRVALLEN(attr);
    if (vallen == newvallen)
	return attr + 2;

    len += newvallen - vallen;
    if (newvallen > vallen) {
	new = realloc(*buf, len + 20);
	if (!new) {
	    debug(DBG_ERR, "resizeattr: malloc failed");
	    return NULL;
	}
	if (new != *buf) {
	    attr += new - *buf;
	    attrs = new + 20;
	    *buf = new;
	}
    }
    memmove(attr + 2 + newvallen, attr + 2 + vallen, len - (attr - attrs + newvallen));
    attr[1] = newvallen + 2;
    ((uint16_t *)*buf)[1] = htons(len + 20);
    return attr + 2;
}
		
int rewriteusername(struct request *rq, char *in) {
    size_t nmatch = 10, reslen = 0, start = 0;
    regmatch_t pmatch[10], *pfield;
    int i;
    unsigned char *result;
    char *out = rq->from->conf->rewriteusernamereplacement;
    
    if (regexec(rq->from->conf->rewriteusernameregex, in, nmatch, pmatch, 0)) {
	debug(DBG_DBG, "rewriteattr: username not matching, no rewrite");
	return 1;
    }
    
    rq->origusername = stringcopy(in, 0);
    if (!rq->origusername)
	return 0;
    
    for (i = start; out[i]; i++) {
	if (out[i] == '\\' && out[i + 1] >= '1' && out[i + 1] <= '9') {
	    pfield = &pmatch[out[i + 1] - '0'];
	    if (pfield->rm_so >= 0) {
		reslen += i - start + pfield->rm_eo - pfield->rm_so;
		start = i + 2;
	    }
	    i++;
	}
    }
    reslen += i - start;

    result = resizeattr(&rq->buf, reslen, RAD_Attr_User_Name);
    if (!result)
	return 0;
    
    start = 0;
    reslen = 0;
    for (i = start; out[i]; i++) {
	if (out[i] == '\\' && out[i + 1] >= '1' && out[i + 1] <= '9') {
	    pfield = &pmatch[out[i + 1] - '0'];
	    if (pfield->rm_so >= 0) {
		memcpy(result + reslen, out + start, i - start);
		reslen += i - start;
		memcpy(result + reslen, in + pfield->rm_so, pfield->rm_eo - pfield->rm_so);
		reslen += pfield->rm_eo - pfield->rm_so;
		start = i + 2;
	    }
	    i++;
	}
    }

    memcpy(result + reslen, out + start, i - start);
    reslen += i - start;
    memcpy(in, result, reslen);
    in[reslen] = '\0';
    return 1;
}

const char *radmsgtype2string(uint8_t code) {
    static const char *rad_msg_names[] = {
	"", "Access-Request", "Access-Accept", "Access-Reject",
	"Accounting-Request", "Accounting-Response", "", "",
	"", "", "", "Access-Challenge",
	"Status-Server", "Status-Client"
    };
    return code < 14 && *rad_msg_names[code] ? rad_msg_names[code] : "Unknown";
}

void char2hex(char *h, unsigned char c) {
    static const char hexdigits[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    h[0] = hexdigits[c / 16];
    h[1] = hexdigits[c % 16];
    return;
}

char *radattr2ascii(char *ascii, size_t len, unsigned char *attr) {
    int i, l;
    char *s, *d;

    if (!attr || len == 1) {
	*ascii = '\0';
	return ascii;
    }

    l = ATTRVALLEN(attr);
    s = (char *)ATTRVAL(attr);
    d = ascii;

    for (i = 0; i < l; i++) {
	if (s[i] > 31 && s[i] < 127) {
	    *d++ = s[i];
	    if (d - ascii == len - 1)
		break;
	} else {
	    if (d - ascii > len - 4)
		break;
	    *d++ = '%';
	    char2hex(d, s[i]);
	    d += 2;
	    if (d - ascii == len - 1)
		break;
	}
    }
    *d = '\0';
    return ascii;
}

void acclog(unsigned char *attrs, int length, char *host) {
    unsigned char *attr;
    char username[760];
    
    attr = attrget(attrs, length, RAD_Attr_User_Name);
    if (!attr) {
	debug(DBG_INFO, "acclog: accounting-request from %s without username attribute", host);
	return;
    }
    radattr2ascii(username, sizeof(username), attr);
    debug(DBG_INFO, "acclog: accounting-request from %s with username: %s", host, username);
}
	
void respondaccounting(struct request *rq) {
    unsigned char *resp;

    resp = malloc(20);
    if (!resp) {
	debug(DBG_ERR, "respondaccounting: malloc failed");
	return;
    }
    memcpy(resp, rq->buf, 20);
    resp[0] = RAD_Accounting_Response;
    resp[2] = 0;
    resp[3] = 20;
    debug(DBG_DBG, "respondaccounting: responding to %s", rq->from->conf->host);
    sendreply(rq->from, resp, &rq->fromsa, rq->fromudpsock);
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
    debug(DBG_DBG, "respondstatusserver: responding to %s", rq->from->conf->host);
    sendreply(rq->from, resp, &rq->fromsa, rq->fromudpsock);
}

void respondreject(struct request *rq, char *message) {
    unsigned char *resp;
    int len = 20;

    if (message && *message)
	len += 2 + strlen(message);
    
    resp = malloc(len);
    if (!resp) {
	debug(DBG_ERR, "respondreject: malloc failed");
	return;
    }
    memcpy(resp, rq->buf, 20);
    resp[0] = RAD_Access_Reject;
    *(uint16_t *)(resp + 2) = htons(len);
    if (message && *message) {
	resp[20] = RAD_Attr_Reply_Message;
	resp[21] = len - 20;
	memcpy(resp + 22, message, len - 22);
    }
    sendreply(rq->from, resp, &rq->fromsa, rq->fromudpsock);
}

struct clsrvconf *choosesrvconf(struct list *srvconfs) {
    struct list_node *entry;
    struct clsrvconf *server, *best = NULL, *first = NULL;

    for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	server = (struct clsrvconf *)entry->data;
	if (!server->servers)
	    return server;
	if (!first)
	    first = server;
	if (!server->servers->connectionok)
	    continue;
	if (!server->servers->lostrqs)
	    return server;
	if (!best) {
	    best = server;
	    continue;
	}
	if (server->servers->lostrqs < best->servers->lostrqs)
	    best = server;
    }
    return best ? best : first;
}

struct server *findserver(struct realm **realm, char *id, uint8_t acc) {
    struct clsrvconf *srvconf;
    
    *realm = id2realm(realms, id);
    if (!*realm)
	return NULL;
    debug(DBG_DBG, "found matching realm: %s", (*realm)->name);
    srvconf = choosesrvconf(acc ? (*realm)->accsrvconfs : (*realm)->srvconfs);
    if (!srvconf)
	return NULL;
    if (!acc && !srvconf->servers)
	adddynamicrealmserver(*realm, srvconf, id);
    return srvconf->servers;
}

/* returns 0 if validation/authentication fails, else 1 */
int radsrv(struct request *rq) {
    uint8_t code, id, *auth, *attrs, *attr;
    uint16_t len;
    struct server *to = NULL;
    char username[254], userascii[760];
    unsigned char newauth[16];
    struct realm *realm = NULL;
    
    code = *(uint8_t *)rq->buf;
    id = *(uint8_t *)(rq->buf + 1);
    len = RADLEN(rq->buf);
    auth = (uint8_t *)(rq->buf + 4);

    debug(DBG_DBG, "radsrv: code %d, id %d, length %d", code, id, len);
    
    if (code != RAD_Access_Request && code != RAD_Status_Server && code != RAD_Accounting_Request) {
	debug(DBG_INFO, "radsrv: server currently accepts only access-requests, accounting-requests and status-server, ignoring");
	goto exit;
    }

    len -= 20;
    attrs = rq->buf + 20;

    if (!attrvalidate(attrs, len)) {
	debug(DBG_WARN, "radsrv: attribute validation failed, ignoring packet");
	goto errvalauth;
    }

    attr = attrget(attrs, len, RAD_Attr_Message_Authenticator);
    if (attr && (ATTRVALLEN(attr) != 16 || !checkmessageauth(rq->buf, ATTRVAL(attr), rq->from->conf->secret))) {
	debug(DBG_WARN, "radsrv: message authentication failed");
	goto errvalauth;
    }

    if (code == RAD_Status_Server) {
	respondstatusserver(rq);
	goto exit;
    }
    
    /* below: code == RAD_Access_Request || code == RAD_Accounting_Request */

    if (code == RAD_Accounting_Request) {
	memset(newauth, 0, 16);
	if (!validauth(rq->buf, newauth, (unsigned char *)rq->from->conf->secret)) {
	    debug(DBG_WARN, "radsrv: Accounting-Request message authentication failed");
	    goto errvalauth;
	}
    }
    
    if (rq->from->conf->rewrite) {
	dorewrite(rq->buf, rq->from->conf->rewrite);
	len = RADLEN(rq->buf) - 20;
    }
    
    attr = attrget(attrs, len, RAD_Attr_User_Name);
    if (!attr) {
	if (code == RAD_Accounting_Request) {
	    acclog(attrs, len, rq->from->conf->host);
	    respondaccounting(rq);
	} else
	    debug(DBG_WARN, "radsrv: ignoring access request, no username attribute");
	goto exit;
    }
    memcpy(username, ATTRVAL(attr), ATTRVALLEN(attr));
    username[ATTRVALLEN(attr)] = '\0';
    radattr2ascii(userascii, sizeof(userascii), attr);

    if (rq->from->conf->rewriteusernameregex) {
	if (!rewriteusername(rq, username)) {
	    debug(DBG_WARN, "radsrv: username malloc failed, ignoring request");
	    goto exit;
	}
	len = RADLEN(rq->buf) - 20;
	auth = (uint8_t *)(rq->buf + 4);
	attrs = rq->buf + 20;
    }

    debug(DBG_DBG, "%s with username: %s", radmsgtype2string(code), userascii);
    
    to = findserver(&realm, username, code == RAD_Accounting_Request);
    if (!realm) {
	debug(DBG_INFO, "radsrv: ignoring request, don't know where to send it");
	goto exit;
    }
    if (!to) {
	if (realm->message && code == RAD_Access_Request) {
	    debug(DBG_INFO, "radsrv: sending reject to %s for %s", rq->from->conf->host, userascii);
	    respondreject(rq, realm->message);
	} else if (realm->accresp && code == RAD_Accounting_Request) {
	    acclog(attrs, len, rq->from->conf->host);
	    respondaccounting(rq);
	}
	goto exit;
    }
    
    if (options.loopprevention && !strcmp(rq->from->conf->name, to->conf->name)) {
	debug(DBG_INFO, "radsrv: Loop prevented, not forwarding request from client %s to server %s, discarding",
	      rq->from->conf->name, to->conf->name);
	goto exit;
    }

    if (rqinqueue(to, rq->from, id, code)) {
	debug(DBG_INFO, "radsrv: already got %s from host %s with id %d, ignoring",
	      radmsgtype2string(code), rq->from->conf->host, id);
	goto exit;
    }
    
    if (code != RAD_Accounting_Request) {
	if (!RAND_bytes(newauth, 16)) {
	    debug(DBG_WARN, "radsrv: failed to generate random auth");
	    goto exit;
	}
    }

#ifdef DEBUG
    printfchars(NULL, "auth", "%02x ", auth, 16);
#endif

    attr = attrget(attrs, len, RAD_Attr_User_Password);
    if (attr) {
	debug(DBG_DBG, "radsrv: found userpwdattr with value length %d", ATTRVALLEN(attr));
	if (!pwdrecrypt(ATTRVAL(attr), ATTRVALLEN(attr), rq->from->conf->secret, to->conf->secret, auth, newauth))
	    goto exit;
    }
    
    attr = attrget(attrs, len, RAD_Attr_Tunnel_Password);
    if (attr) {
	debug(DBG_DBG, "radsrv: found tunnelpwdattr with value length %d", ATTRVALLEN(attr));
	if (!pwdrecrypt(ATTRVAL(attr), ATTRVALLEN(attr), rq->from->conf->secret, to->conf->secret, auth, newauth))
	    goto exit;
    }

    rq->origid = id;
    memcpy(rq->origauth, auth, 16);
    memcpy(auth, newauth, 16);
    sendrq(to, rq);
    return 1;
    
 exit:
    freerqdata(rq);
    return 1;

 errvalauth:
    freerqdata(rq);
    return 0;
}

int replyh(struct server *server, unsigned char *buf) {
    struct client *from;
    struct request *rq;
    int i, len, sublen;
    unsigned char *messageauth, *subattrs, *attrs, *attr, *username;
    struct sockaddr_storage fromsa;
    char tmp[760], stationid[760];
    
    server->connectionok = 1;
    server->lostrqs = 0;
	
    i = buf[1]; /* i is the id */

    if (*buf != RAD_Access_Accept && *buf != RAD_Access_Reject && *buf != RAD_Access_Challenge
	&& *buf != RAD_Accounting_Response) {
	debug(DBG_INFO, "replyh: discarding message type %s, accepting only access accept, access reject, access challenge and accounting response messages", radmsgtype2string(*buf));
	return 0;
    }
    debug(DBG_DBG, "got %s message with id %d", radmsgtype2string(*buf), i);

    rq = server->requests + i;

    pthread_mutex_lock(&server->newrq_mutex);
    if (!rq->buf || !rq->tries) {
	pthread_mutex_unlock(&server->newrq_mutex);
	debug(DBG_INFO, "replyh: no matching request sent with this id, ignoring reply");
	return 0;
    }

    if (rq->received) {
	pthread_mutex_unlock(&server->newrq_mutex);
	debug(DBG_INFO, "replyh: already received, ignoring reply");
	return 0;
    }
	
    if (!validauth(buf, rq->buf + 4, (unsigned char *)server->conf->secret)) {
	pthread_mutex_unlock(&server->newrq_mutex);
	debug(DBG_WARN, "replyh: invalid auth, ignoring reply");
	return 0;
    }
	
    len = RADLEN(buf) - 20;
    attrs = buf + 20;

    if (!attrvalidate(attrs, len)) {
	pthread_mutex_unlock(&server->newrq_mutex);
	debug(DBG_WARN, "replyh: attribute validation failed, ignoring reply");
	return 0;
    }
	
    /* Message Authenticator */
    messageauth = attrget(attrs, len, RAD_Attr_Message_Authenticator);
    if (messageauth) {
	if (ATTRVALLEN(messageauth) != 16) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    debug(DBG_WARN, "replyh: illegal message auth attribute length, ignoring reply");
	    return 0;
	}
	memcpy(tmp, buf + 4, 16);
	memcpy(buf + 4, rq->buf + 4, 16);
	if (!checkmessageauth(buf, ATTRVAL(messageauth), server->conf->secret)) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    debug(DBG_WARN, "replyh: message authentication failed, ignoring reply");
	    return 0;
	}
	memcpy(buf + 4, tmp, 16);
	debug(DBG_DBG, "replyh: message auth ok");
    }
    
    gettimeofday(&server->lastrcv, NULL);
    
    if (*rq->buf == RAD_Status_Server) {
	rq->received = 1;
	pthread_mutex_unlock(&server->newrq_mutex);
	debug(DBG_DBG, "replyh: got status server response from %s", server->conf->host);
	return 0;
    }

    gettimeofday(&server->lastreply, NULL);
    
    from = rq->from;
    if (!from) {
	pthread_mutex_unlock(&server->newrq_mutex);
	debug(DBG_INFO, "replyh: client gone, ignoring reply");
	return 0;
    }
	
    if (server->conf->rewrite) {
	dorewrite(buf, server->conf->rewrite);
	len = RADLEN(buf) - 20;
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
		    rq, server->conf->secret, from->conf->secret) ||
	    !msmppe(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Recv_Key, "MS MPPE Recv Key",
		    rq, server->conf->secret, from->conf->secret))
	    break;
    }
    if (attr) {
	pthread_mutex_unlock(&server->newrq_mutex);
	debug(DBG_WARN, "replyh: MS attribute handling failed, ignoring reply");
	return 0;
    }
	
    if (*buf == RAD_Access_Accept || *buf == RAD_Access_Reject || *buf == RAD_Accounting_Response) {
	attr = attrget(rq->buf + 20, RADLEN(rq->buf) - 20, RAD_Attr_User_Name);
	if (attr) {
	    radattr2ascii(tmp, sizeof(tmp), attr);
	    attr = attrget(rq->buf + 20, RADLEN(rq->buf) - 20, RAD_Attr_Calling_Station_Id);
	    if (attr) {
		radattr2ascii(stationid, sizeof(stationid), attr);
		debug(DBG_INFO, "%s for user %s stationid %s from %s",
		      radmsgtype2string(*buf), tmp, stationid, server->conf->host);
	    } else
		debug(DBG_INFO, "%s for user %s from %s", radmsgtype2string(*buf), tmp, server->conf->host);
	}
    }
	
    buf[1] = (char)rq->origid;
    memcpy(buf + 4, rq->origauth, 16);
#ifdef DEBUG	
    printfchars(NULL, "origauth/buf+4", "%02x ", buf + 4, 16);
#endif

    if (rq->origusername) {
	username = resizeattr(&buf, strlen(rq->origusername), RAD_Attr_User_Name);
	if (!username) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    debug(DBG_WARN, "replyh: malloc failed, ignoring reply");
	    return 0;
	}
	memcpy(username, rq->origusername, strlen(rq->origusername));
	len = RADLEN(buf) - 20;
	attrs = buf + 20;
	if (messageauth)
	    messageauth = attrget(attrs, len, RAD_Attr_Message_Authenticator);
    }
	
    if (messageauth) {
	if (!createmessageauth(buf, ATTRVAL(messageauth), from->conf->secret)) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    debug(DBG_WARN, "replyh: failed to create authenticator, malloc failed?, ignoring reply");
	    return 0;
	}
	debug(DBG_DBG, "replyh: computed messageauthattr");
    }

    fromsa = rq->fromsa; /* only needed for UDP */
    /* once we set received = 1, rq may be reused */
    rq->received = 1;

    debug(DBG_INFO, "replyh: passing reply to client %s", from->conf->name);
    sendreply(from, buf, &fromsa, rq->fromudpsock);
    pthread_mutex_unlock(&server->newrq_mutex);
    return 1;
}

/* code for removing state not finished */
void *clientwr(void *arg) {
    struct server *server = (struct server *)arg;
    struct request *rq;
    pthread_t clientrdth;
    int i, secs, dynconffail = 0;
    uint8_t rnd;
    struct timeval now, laststatsrv;
    struct timespec timeout;
    struct request statsrvrq;
    unsigned char statsrvbuf[38];
    struct clsrvconf *conf;
    
    conf = server->conf;
    
    if (server->dynamiclookuparg && !dynamicconfig(server)) {
	dynconffail = 1;
	goto errexit;
    }
    
    if (!conf->addrinfo && !resolvepeer(conf, 0)) {
	debug(DBG_WARN, "failed to resolve host %s port %s", conf->host ? conf->host : "(null)", conf->port ? conf->port : "(null)");
	goto errexit;
    }

    memset(&timeout, 0, sizeof(struct timespec));
    
    if (conf->statusserver) {
	memset(&statsrvrq, 0, sizeof(struct request));
	memset(statsrvbuf, 0, sizeof(statsrvbuf));
	statsrvbuf[0] = RAD_Status_Server;
	statsrvbuf[3] = 38;
	statsrvbuf[20] = RAD_Attr_Message_Authenticator;
	statsrvbuf[21] = 18;
	gettimeofday(&server->lastrcv, NULL);
	gettimeofday(&laststatsrv, NULL);
    }

    if (conf->pdef->connecter) {
	if (!conf->pdef->connecter(server, NULL, server->dynamiclookuparg ? 6 : 0, "clientwr"))
	    goto errexit;
	server->connectionok = 1;
	if (pthread_create(&clientrdth, NULL, conf->pdef->clientconnreader, (void *)server)) {
	    debug(DBG_ERR, "clientwr: pthread_create failed");
	    goto errexit;
	}
    } else
	server->connectionok = 1;
    
    for (;;) {
	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->newrq) {
	    gettimeofday(&now, NULL);
	    /* random 0-7 seconds */
	    RAND_bytes(&rnd, 1);
	    rnd /= 32;
	    if (conf->statusserver) {
		secs = server->lastrcv.tv_sec > laststatsrv.tv_sec ? server->lastrcv.tv_sec : laststatsrv.tv_sec;
		if (!timeout.tv_sec || timeout.tv_sec > secs + STATUS_SERVER_PERIOD + rnd)
		    timeout.tv_sec = secs + STATUS_SERVER_PERIOD + rnd;
	    } else {
		if (!timeout.tv_sec || timeout.tv_sec > now.tv_sec + STATUS_SERVER_PERIOD + rnd)
		    timeout.tv_sec = now.tv_sec + STATUS_SERVER_PERIOD + rnd;
	    }
#if 0
	    if (timeout.tv_sec > now.tv_sec)
		debug(DBG_DBG, "clientwr: waiting up to %ld secs for new request", timeout.tv_sec - now.tv_sec);
#endif	    
	    pthread_cond_timedwait(&server->newrq_cond, &server->newrq_mutex, &timeout);
	    timeout.tv_sec = 0;
	}
	if (server->newrq) {
	    debug(DBG_DBG, "clientwr: got new request");
	    server->newrq = 0;
	}
#if 0	
	else
	    debug(DBG_DBG, "clientwr: request timer expired, processing request queue");
#endif	
	pthread_mutex_unlock(&server->newrq_mutex);

	for (i = 0; i < MAX_REQUESTS; i++) {
	    if (server->clientrdgone) {
		pthread_join(clientrdth, NULL);
		goto errexit;
	    }
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
		    freerqdata(rq);
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

	    if (rq->tries == (*rq->buf == RAD_Status_Server ? 1 : conf->retrycount + 1)) {
		debug(DBG_DBG, "clientwr: removing expired packet from queue");
		if (conf->statusserver) {
		    if (*rq->buf == RAD_Status_Server) {
			debug(DBG_WARN, "clientwr: no status server response, %s dead?", conf->host);
			if (server->lostrqs < 255)
			    server->lostrqs++;
		    }
                } else {
		    debug(DBG_WARN, "clientwr: no server response, %s dead?", conf->host);
		    if (server->lostrqs < 255)
			server->lostrqs++;
		}
		freerqdata(rq);
		/* setting this to NULL means that it can be reused */
		rq->buf = NULL;
		pthread_mutex_unlock(&server->newrq_mutex);
		continue;
	    }
            pthread_mutex_unlock(&server->newrq_mutex);

	    rq->expiry.tv_sec = now.tv_sec + conf->retryinterval;
	    if (!timeout.tv_sec || rq->expiry.tv_sec < timeout.tv_sec)
		timeout.tv_sec = rq->expiry.tv_sec;
	    rq->tries++;
	    conf->pdef->clientradput(server, server->requests[i].buf);
	}
	if (conf->statusserver) {
	    secs = server->lastrcv.tv_sec > laststatsrv.tv_sec ? server->lastrcv.tv_sec : laststatsrv.tv_sec;
	    gettimeofday(&now, NULL);
	    if (now.tv_sec - secs > STATUS_SERVER_PERIOD) {
		laststatsrv = now;
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
		debug(DBG_DBG, "clientwr: sending status server to %s", conf->host);
		sendrq(server, &statsrvrq);
	    }
	}
    }
 errexit:
    conf->servers = NULL;
    if (server->dynamiclookuparg) {
	removeserversubrealms(realms, conf);
	if (dynconffail)
	    free(conf);
	else
	    freeclsrvconf(conf);
    }
    freeserver(server, 1);
    ERR_remove_state(0);
    return NULL;
}

void createlistener(uint8_t type, char *arg) {
    pthread_t th;
    struct clsrvconf *listenres;
    struct addrinfo *res;
    int s = -1, on = 1, *sp = NULL;
    
    listenres = resolve_hostport(type, arg, protodefs[type].portdefault);
    if (!listenres)
	debugx(1, DBG_ERR, "createlistener: failed to resolve %s", arg);
    
    for (res = listenres->addrinfo; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            debug(DBG_WARN, "createlistener: socket failed");
            continue;
        }
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef IPV6_V6ONLY
	if (res->ai_family == AF_INET6)
	    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif		
	if (bind(s, res->ai_addr, res->ai_addrlen)) {
	    debug(DBG_WARN, "createlistener: bind failed");
	    close(s);
	    s = -1;
	    continue;
	}

	sp = malloc(sizeof(int));
        if (!sp)
            debugx(1, DBG_ERR, "malloc failed");
	*sp = s;
	if (pthread_create(&th, NULL, protodefs[type].listener, (void *)sp))
            debugx(1, DBG_ERR, "pthread_create failed");
	pthread_detach(th);
    }
    if (!sp)
	debugx(1, DBG_ERR, "createlistener: socket/bind failed");
    
    debug(DBG_WARN, "createlistener: listening for %s on %s:%s", protodefs[type].name,
	  listenres->host ? listenres->host : "*", listenres->port);
    freeclsrvres(listenres);
}

void createlisteners(uint8_t type, char **args) {
    int i;

    if (args)
	for (i = 0; args[i]; i++)
	    createlistener(type, args[i]);
    else
	createlistener(type, NULL);
}

#ifdef DEBUG
void ssl_info_callback(const SSL *ssl, int where, int ret) {
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

SSL_CTX *tlscreatectx(uint8_t type, struct tls *conf) {
    SSL_CTX *ctx = NULL;
    STACK_OF(X509_NAME) *calist;
    X509_STORE *x509_s;
    int i;
    unsigned long error;

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

    switch (type) {
    case RAD_TLS:
	ctx = SSL_CTX_new(TLSv1_method());
#ifdef DEBUG	
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
#endif	
	break;
    case RAD_DTLS:
	ctx = SSL_CTX_new(DTLSv1_method());
#ifdef DEBUG	
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);
#endif	
	SSL_CTX_set_read_ahead(ctx, 1);
	break;
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
	!SSL_CTX_check_private_key(ctx) ||
	!SSL_CTX_load_verify_locations(ctx, conf->cacertfile, conf->cacertpath)) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
	debug(DBG_ERR, "tlscreatectx: Error initialising SSL/TLS in TLS context %s", conf->name);
	SSL_CTX_free(ctx);
	return NULL;
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
	debug(DBG_ERR, "tlscreatectx: Error adding CA subjects in TLS context %s", conf->name);
	SSL_CTX_free(ctx);
	return NULL;
    }
    ERR_clear_error(); /* add_dir_cert_subj returns errors on success */
    SSL_CTX_set_client_CA_list(ctx, calist);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
    SSL_CTX_set_verify_depth(ctx, MAX_CERT_DEPTH + 1);

    if (conf->crlcheck) {
	x509_s = SSL_CTX_get_cert_store(ctx);
	X509_STORE_set_flags(x509_s, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

    debug(DBG_DBG, "tlscreatectx: created TLS context %s", conf->name);
    return ctx;
}

SSL_CTX *tlsgetctx(uint8_t type, char *alt1, char *alt2) {
    struct tls *t;

    t = hash_read(tlsconfs, alt1, strlen(alt1));
    if (!t) {
	t = hash_read(tlsconfs, alt2, strlen(alt2));
	if (!t)
	    return NULL;
    }

    switch (type) {
    case RAD_TLS:
	if (!t->tlsctx)
	    t->tlsctx = tlscreatectx(RAD_TLS, t);
	return t->tlsctx;
    case RAD_DTLS:
	if (!t->dtlsctx)
	    t->dtlsctx = tlscreatectx(RAD_DTLS, t);
	return t->dtlsctx;
    }
    return NULL;
}

struct list *addsrvconfs(char *value, char **names) {
    struct list *conflist;
    int n;
    struct list_node *entry;
    struct clsrvconf *conf = NULL;
    
    if (!names || !*names)
	return NULL;
    
    conflist = list_create();
    if (!conflist) {
	debug(DBG_ERR, "malloc failed");
	return NULL;
    }

    for (n = 0; names[n]; n++) {
	for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	    conf = (struct clsrvconf *)entry->data;
	    if (!strcasecmp(names[n], conf->name))
		break;
	}
	if (!entry) {
	    debug(DBG_ERR, "addsrvconfs failed for realm %s, no server named %s", value, names[n]);
	    list_destroy(conflist);
	    return NULL;
	}
	if (!list_push(conflist, conf)) {
	    debug(DBG_ERR, "malloc failed");
	    list_destroy(conflist);
	    return NULL;
	}
	debug(DBG_DBG, "addsrvconfs: added server %s for realm %s", conf->name, value);
    }
    return conflist;
}

void freerealm(struct realm *realm) {
    if (!realm)
	return;
    free(realm->name);
    free(realm->message);
    regfree(&realm->regex);
    pthread_mutex_destroy(&realm->subrealms_mutex);
    if (realm->subrealms)
	list_destroy(realm->subrealms);
    if (realm->srvconfs) {
	/* emptying list without freeing data */
	while (list_shift(realm->srvconfs));
	list_destroy(realm->srvconfs);
    }
    if (realm->accsrvconfs) {
	/* emptying list without freeing data */
	while (list_shift(realm->accsrvconfs));
	list_destroy(realm->accsrvconfs);
    }
    free(realm);
}

struct realm *addrealm(struct list *realmlist, char *value, char **servers, char **accservers, char *message, uint8_t accresp) {
    int n;
    struct realm *realm;
    char *s, *regex = NULL;
    
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
	if (!regex) {
	    debug(DBG_ERR, "malloc failed");
	    realm = NULL;
	    goto exit;
	}
	debug(DBG_DBG, "addrealm: constructed regexp %s from %s", regex, value);
    }

    realm = malloc(sizeof(struct realm));
    if (!realm) {
	debug(DBG_ERR, "malloc failed");
	goto exit;
    }
    memset(realm, 0, sizeof(struct realm));
    
    if (pthread_mutex_init(&realm->subrealms_mutex, NULL)) {
	debug(DBG_ERR, "mutex init failed");
	free(realm);
	realm = NULL;
	goto exit;
    }

    realm->name = stringcopy(value, 0);
    if (!realm->name) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    if (message && strlen(message) > 253) {
	debug(DBG_ERR, "ReplyMessage can be at most 253 bytes");
	goto errexit;
    }
    realm->message = message;
    realm->accresp = accresp;
    
    if (regcomp(&realm->regex, regex ? regex : value + 1, REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
	debug(DBG_ERR, "addrealm: failed to compile regular expression %s", regex ? regex : value + 1);
	goto errexit;
    }
    
    if (servers && *servers) {
	realm->srvconfs = addsrvconfs(value, servers);
	if (!realm->srvconfs)
	    goto errexit;
    }
    
    if (accservers && *accservers) {
	realm->accsrvconfs = addsrvconfs(value, accservers);
	if (!realm->accsrvconfs)
	    goto errexit;
    }

    if (!list_push(realmlist, realm)) {
	debug(DBG_ERR, "malloc failed");
	pthread_mutex_destroy(&realm->subrealms_mutex);
	goto errexit;
    }
    
    debug(DBG_DBG, "addrealm: added realm %s", value);
    goto exit;

 errexit:
    freerealm(realm);
    realm = NULL;
    
 exit:
    free(regex);
    if (servers) {
	for (n = 0; servers[n]; n++)
	    free(servers[n]);
	free(servers);
    }
    if (accservers) {
	for (n = 0; accservers[n]; n++)
	    free(accservers[n]);
	free(accservers);
    }
    return realm;
}

void adddynamicrealmserver(struct realm *realm, struct clsrvconf *conf, char *id) {
    struct clsrvconf *srvconf;
    struct realm *newrealm = NULL;
    char *realmname, *s;
    pthread_t clientth;
    
    if (!conf->dynamiclookupcommand)
	return;

    /* create dynamic for the realm (string after last @, exit if nothing after @ */
    realmname = strrchr(id, '@');
    if (!realmname)
	return;
    realmname++;
    if (!*realmname)
	return;
    for (s = realmname; *s; s++)
	if (*s != '.' && *s != '-' && !isalnum((int)*s))
	    return;
    
    pthread_mutex_lock(&realm->subrealms_mutex);
    /* exit if we now already got a matching subrealm */
    if (id2realm(realm->subrealms, id))
	goto exit;
    srvconf = malloc(sizeof(struct clsrvconf));
    if (!srvconf) {
	debug(DBG_ERR, "malloc failed");
	goto exit;
    }
    *srvconf = *conf;
    if (!addserver(srvconf))
	goto errexit;

    if (!realm->subrealms)
	realm->subrealms = list_create();
    if (!realm->subrealms)
	goto errexit;
    newrealm = addrealm(realm->subrealms, realmname, NULL, NULL, NULL, 0);
    if (!newrealm)
	goto errexit;

    /* add server and accserver to newrealm */
    newrealm->srvconfs = list_create();
    if (!newrealm->srvconfs || !list_push(newrealm->srvconfs, srvconf)) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    newrealm->accsrvconfs = list_create();
    if (!newrealm->accsrvconfs || !list_push(newrealm->accsrvconfs, srvconf)) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }

    srvconf->servers->dynamiclookuparg = stringcopy(realmname, 0);

    if (pthread_create(&clientth, NULL, clientwr, (void *)(srvconf->servers))) {
	debug(DBG_ERR, "pthread_create failed");
	goto errexit;
    }
    pthread_detach(clientth);
    goto exit;
    
 errexit:
    if (newrealm) {
	list_removedata(realm->subrealms, newrealm);
	freerealm(newrealm);
	if (!list_first(realm->subrealms)) {
	    list_destroy(realm->subrealms);
	    realm->subrealms = NULL;
	}
    }
    freeserver(srvconf->servers, 1);
    free(srvconf);
    debug(DBG_ERR, "failed to create dynamic server");

 exit:
    pthread_mutex_unlock(&realm->subrealms_mutex);
}

int dynamicconfig(struct server *server) {
    int ok, fd[2], status;
    pid_t pid;
    struct clsrvconf *conf = server->conf;
    struct gconffile *cf = NULL;
    
    /* for now we only learn hostname/address */
    debug(DBG_DBG, "dynamicconfig: need dynamic server config for %s", server->dynamiclookuparg);

    if (pipe(fd) > 0) {
	debug(DBG_ERR, "dynamicconfig: pipe error");
	goto errexit;
    }
    pid = fork();
    if (pid < 0) {
	debug(DBG_ERR, "dynamicconfig: fork error");
	close(fd[0]);
	close(fd[1]);
	goto errexit;
    } else if (pid == 0) {
	/* child */
	close(fd[0]);
	if (fd[1] != STDOUT_FILENO) {
	    if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO)
		debugx(1, DBG_ERR, "dynamicconfig: dup2 error for command %s", conf->dynamiclookupcommand);
	    close(fd[1]);
	}
	if (execlp(conf->dynamiclookupcommand, conf->dynamiclookupcommand, server->dynamiclookuparg, NULL) < 0)
	    debugx(1, DBG_ERR, "dynamicconfig: exec error for command %s", conf->dynamiclookupcommand);
    }

    close(fd[1]);
    pushgconffile(&cf, fdopen(fd[0], "r"), conf->dynamiclookupcommand);
    ok = getgenericconfig(&cf, NULL,
			  "Server", CONF_CBK, confserver_cb, (void *)conf,
			  NULL
			  );
    freegconf(&cf);
	
    if (waitpid(pid, &status, 0) < 0) {
	debug(DBG_ERR, "dynamicconfig: wait error");
	goto errexit;
    }
    
    if (status) {
	debug(DBG_INFO, "dynamicconfig: command exited with status %d", WEXITSTATUS(status));
	goto errexit;
    }

    if (ok)
	return 1;

 errexit:    
    debug(DBG_WARN, "dynamicconfig: failed to obtain dynamic server config");
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

int addrewriteattr(struct clsrvconf *conf) {
    char *v, *w;
    
    v = conf->rewriteattr + 11;
    if (strncasecmp(conf->rewriteattr, "User-Name:/", 11) || !*v)
	return 0;
    /* regexp, remove optional trailing / if present */
    if (v[strlen(v) - 1] == '/')
	v[strlen(v) - 1] = '\0';

    w = strchr(v, '/');
    if (!*w)
	return 0;
    *w = '\0';
    w++;
    
    conf->rewriteusernameregex = malloc(sizeof(regex_t));
    if (!conf->rewriteusernameregex) {
	debug(DBG_ERR, "malloc failed");
	return 0;
    }

    conf->rewriteusernamereplacement = stringcopy(w, 0);
    if (!conf->rewriteusernamereplacement) {
	free(conf->rewriteusernameregex);
	conf->rewriteusernameregex = NULL;
	return 0;
    }
    
    if (regcomp(conf->rewriteusernameregex, v, REG_ICASE | REG_EXTENDED)) {
	free(conf->rewriteusernameregex);
	conf->rewriteusernameregex = NULL;
	free(conf->rewriteusernamereplacement);
	conf->rewriteusernamereplacement = NULL;
	debug(DBG_ERR, "failed to compile regular expression %s", v);
	return 0;
    }

    return 1;
}

/* should accept both names and numeric values, only numeric right now */
uint8_t attrname2val(char *attrname) {
    int val = 0;
    
    val = atoi(attrname);
    return val > 0 && val < 256 ? val : 0;
}

/* should accept both names and numeric values, only numeric right now */
int vattrname2val(char *attrname, uint32_t *vendor, uint32_t *type) {
    char *s;
    
    *vendor = atoi(attrname);
    s = strchr(attrname, ':');
    if (!s) {
	*type = -1;
	return 1;
    }
    *type = atoi(s + 1);
    return *type >= 0 && *type < 256;
}

struct rewrite *getrewrite(char *alt1, char *alt2) {
    struct rewrite *r;

    if ((r = hash_read(rewriteconfs,  alt1, strlen(alt1))))
	return r;
    if ((r = hash_read(rewriteconfs,  alt2, strlen(alt2))))
	return r;
    return NULL;
}

void addrewrite(char *value, char **attrs, char **vattrs) {
    struct rewrite *rewrite = NULL;
    int i, n;
    uint8_t *a = NULL;
    uint32_t *p, *va = NULL;

    if (attrs) {
	n = 0;
	for (; attrs[n]; n++);
	a = malloc((n + 1) * sizeof(uint8_t));
	if (!a)
	    debugx(1, DBG_ERR, "malloc failed");
    
	for (i = 0; i < n; i++) {
	    if (!(a[i] = attrname2val(attrs[i])))
		debugx(1, DBG_ERR, "addrewrite: invalid attribute %s", attrs[i]);
	    free(attrs[i]);
	}
	free(attrs);
	a[i] = 0;
    }
    
    if (vattrs) {
	n = 0;
	for (; vattrs[n]; n++);
	va = malloc((2 * n + 1) * sizeof(uint32_t));
	if (!va)
	    debugx(1, DBG_ERR, "malloc failed");
    
	for (p = va, i = 0; i < n; i++, p += 2) {
	    if (!vattrname2val(vattrs[i], p, p + 1))
		debugx(1, DBG_ERR, "addrewrite: invalid vendor attribute %s", vattrs[i]);
	    free(vattrs[i]);
	}
	free(vattrs);
	*p = 0;
    }
    
    if (a || va) {
	rewrite = malloc(sizeof(struct rewrite));
	if (!rewrite)
	    debugx(1, DBG_ERR, "malloc failed");
	rewrite->removeattrs = a;
	rewrite->removevendorattrs = va;
    }
    
    if (!hash_insert(rewriteconfs, value, strlen(value), rewrite))
	debugx(1, DBG_ERR, "malloc failed");
    debug(DBG_DBG, "addrewrite: added rewrite block %s", value);
}

void freeclsrvconf(struct clsrvconf *conf) {
    free(conf->name);
    free(conf->host);
    free(conf->port);
    free(conf->secret);
    free(conf->tls);
    free(conf->matchcertattr);
    if (conf->certcnregex)
	regfree(conf->certcnregex);
    if (conf->certuriregex)
	regfree(conf->certuriregex);
    free(conf->confrewrite);
    free(conf->rewriteattr);
    if (conf->rewriteusernameregex)
	regfree(conf->rewriteusernameregex);
    free(conf->rewriteusernamereplacement);
    free(conf->dynamiclookupcommand);
    free(conf->rewrite);
    if (conf->addrinfo)
	freeaddrinfo(conf->addrinfo);
    /* not touching ssl_ctx, clients and servers */
    free(conf);
}

int mergeconfstring(char **dst, char **src) {
    char *t;
    
    if (*src) {
	*dst = *src;
	*src = NULL;
	return 1;
    }
    if (*dst) {
	t = stringcopy(*dst, 0);
	if (!t) {
	    debug(DBG_ERR, "malloc failed");
	    return 0;
	}
	*dst = t;
    }
    return 1;
}

/* assumes dst is a shallow copy */
int mergesrvconf(struct clsrvconf *dst, struct clsrvconf *src) {
    if (!mergeconfstring(&dst->name, &src->name) ||
	!mergeconfstring(&dst->host, &src->host) ||
	!mergeconfstring(&dst->port, &src->port) ||
	!mergeconfstring(&dst->secret, &src->secret) ||
	!mergeconfstring(&dst->tls, &src->tls) ||
	!mergeconfstring(&dst->matchcertattr, &src->matchcertattr) ||
	!mergeconfstring(&dst->confrewrite, &src->confrewrite) ||
	!mergeconfstring(&dst->dynamiclookupcommand, &src->dynamiclookupcommand))
	return 0;
    if (src->pdef)
	dst->pdef = src->pdef;
    dst->statusserver = src->statusserver;
    dst->certnamecheck = src->certnamecheck;
    if (src->retryinterval != 255)
	dst->retryinterval = src->retryinterval;
    if (src->retrycount != 255)
	dst->retrycount = src->retrycount;
    return 1;
}

int confclient_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    struct clsrvconf *conf;
    char *conftype = NULL;
    
    debug(DBG_DBG, "confclient_cb called for %s", block);

    conf = malloc(sizeof(struct clsrvconf));
    if (!conf || !list_push(clconfs, conf))
	debugx(1, DBG_ERR, "malloc failed");
    memset(conf, 0, sizeof(struct clsrvconf));
    conf->certnamecheck = 1;
    
    if (!getgenericconfig(cf, block,
		     "type", CONF_STR, &conftype,
		     "host", CONF_STR, &conf->host,
		     "secret", CONF_STR, &conf->secret,
		     "tls", CONF_STR, &conf->tls,
		     "matchcertificateattribute", CONF_STR, &conf->matchcertattr,
		     "CertificateNameCheck", CONF_BLN, &conf->certnamecheck,
		     "rewrite", CONF_STR, &conf->confrewrite,
		     "rewriteattribute", CONF_STR, &conf->rewriteattr,
		     NULL
			  ))
	debugx(1, DBG_ERR, "configuration error");
    
    conf->name = stringcopy(val, 0);
    if (!conf->host)
	conf->host = stringcopy(val, 0);
    if (!conf->name || !conf->host)
	debugx(1, DBG_ERR, "malloc failed");
	
    if (!conftype)
	debugx(1, DBG_ERR, "error in block %s, option type missing", block);
    conf->type = protoname2int(conftype);
    conf->pdef = &protodefs[conf->type];
    if (!conf->pdef->name)
	debugx(1, DBG_ERR, "error in block %s, unknown transport %s", block, conftype);
    free(conftype);
    
    if (conf->type == RAD_TLS || conf->type == RAD_DTLS) {
	conf->ssl_ctx = conf->tls ? tlsgetctx(conf->type, conf->tls, NULL) : tlsgetctx(conf->type, "defaultclient", "default");
	if (!conf->ssl_ctx)
	    debugx(1, DBG_ERR, "error in block %s, no tls context defined", block);
	if (conf->matchcertattr && !addmatchcertattr(conf))
	    debugx(1, DBG_ERR, "error in block %s, invalid MatchCertificateAttributeValue", block);
    }
    
    conf->rewrite = conf->confrewrite ? getrewrite(conf->confrewrite, NULL) : getrewrite("defaultclient", "default");
    
    if (conf->rewriteattr) {
	if (!addrewriteattr(conf))
	    debugx(1, DBG_ERR, "error in block %s, invalid RewriteAttributeValue", block);
    }
    
    if (!resolvepeer(conf, 0))
	debugx(1, DBG_ERR, "failed to resolve host %s port %s, exiting", conf->host ? conf->host : "(null)", conf->port ? conf->port : "(null)");
    
    if (!conf->secret) {
	if (!conf->pdef->secretdefault)
	    debugx(1, DBG_ERR, "error in block %s, secret must be specified for transport type %s", block, conf->pdef->name);
	conf->secret = stringcopy(conf->pdef->secretdefault, 0);
	if (!conf->secret)
	    debugx(1, DBG_ERR, "malloc failed");
    }
    return 1;
}

int compileserverconfig(struct clsrvconf *conf, const char *block) {
    if (conf->type == RAD_TLS || conf->type == RAD_DTLS) {
    	conf->ssl_ctx = conf->tls ? tlsgetctx(conf->type, conf->tls, NULL) : tlsgetctx(conf->type, "defaultserver", "default");
	if (!conf->ssl_ctx) {
	    debug(DBG_ERR, "error in block %s, no tls context defined", block);
	    return 0;
	}
	if (conf->matchcertattr && !addmatchcertattr(conf)) {
	    debug(DBG_ERR, "error in block %s, invalid MatchCertificateAttributeValue", block);
	    return 0;
	}
    }

    if (!conf->port) {
	conf->port = stringcopy(conf->pdef->portdefault, 0);
	if (!conf->port) {
	    debug(DBG_ERR, "malloc failed");
	    return 0;
	}
    }
    
    if (conf->retryinterval == 255)
	conf->retryinterval = protodefs[conf->type].retryintervaldefault;
    if (conf->retrycount == 255)
	conf->retrycount = protodefs[conf->type].retrycountdefault;
    
    conf->rewrite = conf->confrewrite ? getrewrite(conf->confrewrite, NULL) : getrewrite("defaultserver", "default");

    if (!conf->secret) {
	if (!conf->pdef->secretdefault) {
	    debug(DBG_ERR, "error in block %s, secret must be specified for transport type %s", block, conf->pdef->name);
	    return 0;
	}
	conf->secret = stringcopy(conf->pdef->secretdefault, 0);
	if (!conf->secret) {
	    debug(DBG_ERR, "malloc failed");
	    return 0;
	}
    }
    
    if (!conf->dynamiclookupcommand && !resolvepeer(conf, 0)) {
	debug(DBG_ERR, "failed to resolve host %s port %s, exiting", conf->host ? conf->host : "(null)", conf->port ? conf->port : "(null)");
	return 0;
    }
    return 1;
}
			
int confserver_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    struct clsrvconf *conf, *resconf;
    char *conftype = NULL;
    long int retryinterval = LONG_MIN, retrycount = LONG_MIN;
    
    debug(DBG_DBG, "confserver_cb called for %s", block);

    conf = malloc(sizeof(struct clsrvconf));
    if (!conf) {
	debug(DBG_ERR, "malloc failed");
	return 0;
    }
    memset(conf, 0, sizeof(struct clsrvconf));
    resconf = (struct clsrvconf *)arg;
    if (resconf) {
	conf->statusserver = resconf->statusserver;
	conf->certnamecheck = resconf->certnamecheck;
    } else
	conf->certnamecheck = 1;

    if (!getgenericconfig(cf, block,
			  "type", CONF_STR, &conftype,
			  "host", CONF_STR, &conf->host,
			  "port", CONF_STR, &conf->port,
			  "secret", CONF_STR, &conf->secret,
			  "tls", CONF_STR, &conf->tls,
			  "MatchCertificateAttribute", CONF_STR, &conf->matchcertattr,
			  "rewrite", CONF_STR, &conf->confrewrite,
			  "StatusServer", CONF_BLN, &conf->statusserver,
			  "RetryInterval", CONF_LINT, &retryinterval,
			  "RetryCount", CONF_LINT, &retrycount,
			  "CertificateNameCheck", CONF_BLN, &conf->certnamecheck,
			  "DynamicLookupCommand", CONF_STR, &conf->dynamiclookupcommand,
			  NULL
			  )) {
	debug(DBG_ERR, "configuration error");
	goto errexit;
    }
    
    conf->name = stringcopy(val, 0);
    if (!conf->name) {
        debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    if (!conf->host) {
	conf->host = stringcopy(val, 0);
	if (!conf->host) {
            debug(DBG_ERR, "malloc failed");
	    goto errexit;
        }
    }

    if (!conftype)
	debugx(1, DBG_ERR, "error in block %s, option type missing", block);
    conf->type = protoname2int(conftype);
    conf->pdef = &protodefs[conf->type];
    if (!conf->pdef->name) {
	debug(DBG_ERR, "error in block %s, unknown transport %s", block, conftype);
	free(conftype);
	goto errexit;
    }
    free(conftype);
	    
    if (retryinterval != LONG_MIN) {
	if (retryinterval < 1 || retryinterval > conf->pdef->retryintervalmax) {
	    debug(DBG_ERR, "error in block %s, value of option RetryInterval is %d, must be 1-%d", block, retryinterval, conf->pdef->retryintervalmax);
	    goto errexit;
	}
	conf->retryinterval = (uint8_t)retryinterval;
    } else
	conf->retryinterval = 255;
    
    if (retrycount != LONG_MIN) {
	if (retrycount < 0 || retrycount > conf->pdef->retrycountmax) {
	    debug(DBG_ERR, "error in block %s, value of option RetryCount is %d, must be 0-%d", block, retrycount, conf->pdef->retrycountmax);
	    goto errexit;
	}
	conf->retrycount = (uint8_t)retrycount;
    } else
	conf->retrycount = 255;
    
    if (resconf) {
	if (!mergesrvconf(resconf, conf))
	    goto errexit;
	free(conf);
	conf = resconf;
	if (conf->dynamiclookupcommand) {
	    free(conf->dynamiclookupcommand);
	    conf->dynamiclookupcommand = NULL;
	}
    }

    if (resconf || !conf->dynamiclookupcommand) {
	if (!compileserverconfig(conf, block))
	    goto errexit;
    }
    
    if (resconf)
	return 1;
	
    if (!list_push(srvconfs, conf)) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    return 1;

 errexit:    
    freeclsrvconf(conf);
    return 0;
}

int confrealm_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    char **servers = NULL, **accservers = NULL, *msg = NULL;
    uint8_t accresp = 0;
    
    debug(DBG_DBG, "confrealm_cb called for %s", block);
    
    if (!getgenericconfig(cf, block,
		     "server", CONF_MSTR, &servers,
		     "accountingServer", CONF_MSTR, &accservers,
		     "ReplyMessage", CONF_STR, &msg,
		     "AccountingResponse", CONF_BLN, &accresp,
		     NULL
			  ))
	debugx(1, DBG_ERR, "configuration error");

    addrealm(realms, val, servers, accservers, msg, accresp);
    return 1;
}

int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    struct tls *conf;
    
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
		     "CRLCheck", CONF_BLN, &conf->crlcheck,
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

    conf->name = stringcopy(val, 0);
    if (!conf->name) {
	debug(DBG_ERR, "conftls_cb: malloc failed");
	goto errexit;
    }

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
    free(conf);
    return 0;
}

int confrewrite_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    char **attrs = NULL, **vattrs = NULL;
    
    debug(DBG_DBG, "confrewrite_cb called for %s", block);
    
    if (!getgenericconfig(cf, block,
		     "removeAttribute", CONF_MSTR, &attrs,
		     "removeVendorAttribute", CONF_MSTR, &vattrs,
		     NULL
			  ))
	debugx(1, DBG_ERR, "configuration error");
    addrewrite(val, attrs, vattrs);
    return 1;
}

void getmainconfig(const char *configfile) {
    long int loglevel = LONG_MIN;
    struct gconffile *cfs;

    cfs = openconfigfile(configfile);
    memset(&options, 0, sizeof(options));
    
    clconfs = list_create();
    if (!clconfs)
	debugx(1, DBG_ERR, "malloc failed");
    
    srvconfs = list_create();
    if (!srvconfs)
	debugx(1, DBG_ERR, "malloc failed");
    
    realms = list_create();
    if (!realms)
	debugx(1, DBG_ERR, "malloc failed");    
 
    tlsconfs = hash_create();
    if (!tlsconfs)
	debugx(1, DBG_ERR, "malloc failed");
    
    rewriteconfs = hash_create();
    if (!rewriteconfs)
	debugx(1, DBG_ERR, "malloc failed");    
 
    if (!getgenericconfig(&cfs, NULL,
			  "ListenUDP", CONF_MSTR, &options.listenudp,
			  "ListenTCP", CONF_MSTR, &options.listentcp,
			  "ListenTLS", CONF_MSTR, &options.listentls,
			  "ListenDTLS", CONF_MSTR, &options.listendtls,
			  "ListenAccountingUDP", CONF_MSTR, &options.listenaccudp,
			  "SourceUDP", CONF_STR, &options.sourceudp,
			  "SourceTCP", CONF_STR, &options.sourcetcp,
			  "SourceTLS", CONF_STR, &options.sourcetls,
			  "SourceDTLS", CONF_STR, &options.sourcedtls,
			  "LogLevel", CONF_LINT, &loglevel,
			  "LogDestination", CONF_STR, &options.logdestination,
			  "LoopPrevention", CONF_BLN, &options.loopprevention,
			  "Client", CONF_CBK, confclient_cb, NULL,
			  "Server", CONF_CBK, confserver_cb, NULL,
			  "Realm", CONF_CBK, confrealm_cb, NULL,
			  "TLS", CONF_CBK, conftls_cb, NULL,
			  "Rewrite", CONF_CBK, confrewrite_cb, NULL,
			  NULL
			  ))
	debugx(1, DBG_ERR, "configuration error");
    
    if (loglevel != LONG_MIN) {
	if (loglevel < 1 || loglevel > 4)
	    debugx(1, DBG_ERR, "error in %s, value of option LogLevel is %d, must be 1, 2, 3 or 4", configfile, loglevel);
	options.loglevel = (uint8_t)loglevel;
    }
}

void getargs(int argc, char **argv, uint8_t *foreground, uint8_t *pretend, uint8_t *loglevel, char **configfile) {
    int c;

    while ((c = getopt(argc, argv, "c:d:fpv")) != -1) {
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
	case 'p':
	    *pretend = 1;
	    break;
	case 'v':
		debugx(0, DBG_ERR, "radsecproxy revision $Rev$");
	default:
	    goto usage;
	}
    }
    if (!(argc - optind))
	return;

 usage:
    debugx(1, DBG_ERR, "Usage:\n%s [ -c configfile ] [ -d debuglevel ] [ -f ] [ -p ] [ -v ]", argv[0]);
}

#ifdef SYS_SOLARIS9
int daemon(int a, int b) {
    int i;

    if (fork())
	exit(0);

    setsid();

    for (i = 0; i < 3; i++) {
	close(i);
	open("/dev/null", O_RDWR);
    }
    return 1;
}
#endif

void *sighandler(void *arg) {
    sigset_t sigset;
    int sig;

    for(;;) {
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGPIPE);
	sigwait(&sigset, &sig);
	/* only get SIGPIPE right now, so could simplify below code */
        switch (sig) {
        case 0:
            /* completely ignoring this */
            break;
        case SIGPIPE:
            debug(DBG_WARN, "sighandler: got SIGPIPE, TLS write error?");
            break;
        default:
            debug(DBG_WARN, "sighandler: ignoring signal %d", sig);
        }
    }
}

int main(int argc, char **argv) {
    pthread_t sigth;
    sigset_t sigset;
    struct list_node *entry;
    uint8_t foreground = 0, pretend = 0, loglevel = 0;
    char *configfile = NULL;
    struct clsrvconf *srvconf;
    int i;
    
    debug_init("radsecproxy");
    debug_set_level(DEBUG_LEVEL);
    
    getargs(argc, argv, &foreground, &pretend, &loglevel, &configfile);
    if (loglevel)
	debug_set_level(loglevel);
    getmainconfig(configfile ? configfile : CONFIG_MAIN);
    if (loglevel)
	options.loglevel = loglevel;
    else if (options.loglevel)
	debug_set_level(options.loglevel);
    if (!foreground)
	debug_set_destination(options.logdestination ? options.logdestination : "x-syslog:///");
    free(options.logdestination);

    if (!list_first(clconfs))
	debugx(1, DBG_ERR, "No clients configured, nothing to do, exiting");
    if (!list_first(realms))
	debugx(1, DBG_ERR, "No realms configured, nothing to do, exiting");

    if (pretend)
	debugx(0, DBG_ERR, "All OK so far; exiting since only pretending");

    if (!foreground && (daemon(0, 0) < 0))
	debugx(1, DBG_ERR, "daemon() failed: %s", strerror(errno));
    
    debug(DBG_INFO, "radsecproxy revision $Rev$ starting");

    sigemptyset(&sigset);
    /* exit on all but SIGPIPE, ignore more? */
    sigaddset(&sigset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    pthread_create(&sigth, NULL, sighandler, NULL);

    for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	srvconf = (struct clsrvconf *)entry->data;
	if (srvconf->dynamiclookupcommand)
	    continue;
	if (!addserver(srvconf))
	    debugx(1, DBG_ERR, "failed to add server");
	if (pthread_create(&srvconf->servers->clientth, NULL, clientwr,
			   (void *)(srvconf->servers)))
	    debugx(1, DBG_ERR, "pthread_create failed");
    }
    /* srcprotores for UDP no longer needed */
    if (srcprotores[RAD_UDP]) {
	freeaddrinfo(srcprotores[RAD_UDP]);
	srcprotores[RAD_UDP] = NULL;
    }

    for (i = 0; protodefs[i].name; i++)
	if (protodefs[i].initextra)
	    protodefs[i].initextra();
    
    if (find_clconf_type(RAD_TCP, NULL))
	createlisteners(RAD_TCP, options.listentcp);
    
    if (find_clconf_type(RAD_TLS, NULL))
	createlisteners(RAD_TLS, options.listentls);
    
    if (find_clconf_type(RAD_DTLS, NULL))
	createlisteners(RAD_DTLS, options.listendtls);
    
    if (find_clconf_type(RAD_UDP, NULL)) {
	createlisteners(RAD_UDP, options.listenudp);
	if (options.listenaccudp)
	    createlisteners(RAD_UDP, options.listenaccudp);
    }
    
    /* just hang around doing nothing, anything to do here? */
    for (;;)
	sleep(1000);
}
