/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

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
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "hash.h"
#include "radsecproxy.h"

#ifdef RADPROT_DTLS
#include "debug.h"
#include "util.h"
#include "hostport.h"

static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs();
void *udpdtlsserverrd(void *arg);
int dtlsconnect(struct server *server, struct timeval *when, int timeout, char *text);
void *dtlsclientrd(void *arg);
int clientradputdtls(struct server *server, unsigned char *rad);
void addserverextradtls(struct clsrvconf *conf);
void dtlssetsrcres();
void initextradtls();

static const struct protodefs protodefs = {
    "dtls",
    "radsec", /* secretdefault */
    SOCK_DGRAM, /* socktype */
    "2083", /* portdefault */
    REQUEST_RETRY_COUNT, /* retrycountdefault */
    10, /* retrycountmax */
    REQUEST_RETRY_INTERVAL, /* retryintervaldefault */
    60, /* retryintervalmax */
    DUPLICATE_INTERVAL, /* duplicateintervaldefault */
    setprotoopts, /* setprotoopts */
    getlistenerargs, /* getlistenerargs */
    udpdtlsserverrd, /* listener */
    dtlsconnect, /* connecter */
    dtlsclientrd, /* clientconnreader */
    clientradputdtls, /* clientradput */
    NULL, /* addclient */
    addserverextradtls, /* addserverextra */
    dtlssetsrcres, /* setsrcres */
    initextradtls /* initextra */
};

static int client4_sock = -1;
static int client6_sock = -1;
static struct addrinfo *srcres = NULL;
static uint8_t handle;
static struct commonprotoopts *protoopts = NULL;

const struct protodefs *dtlsinit(uint8_t h) {
    handle = h;
    return &protodefs;
}

static void setprotoopts(struct commonprotoopts *opts) {
    protoopts = opts;
}

static char **getlistenerargs() {
    return protoopts ? protoopts->listenargs : NULL;
}

struct sessioncacheentry {
    pthread_mutex_t mutex;
    struct gqueue *rbios;
    struct timeval expiry;
};

struct dtlsservernewparams {
    struct sessioncacheentry *sesscache;
    int sock;
    struct sockaddr_storage addr;
};

void dtlssetsrcres() {
    if (!srcres)
	srcres =
            resolvepassiveaddrinfo(protoopts ? protoopts->sourcearg : NULL,
                                   AF_UNSPEC, NULL, protodefs.socktype);
}

int udp2bio(int s, struct gqueue *q, int cnt) {
    unsigned char *buf;
    BIO *rbio;

    if (cnt < 1)
	return 0;

    buf = malloc(cnt);
    if (!buf) {
	unsigned char err;
	debug(DBG_ERR, "udp2bio: malloc failed");
	recv(s, &err, 1, 0);
	return 0;
    }

    cnt = recv(s, buf, cnt, 0);
    if (cnt < 1) {
	debug(DBG_WARN, "udp2bio: recv failed");
	free(buf);
	return 0;
    }

    rbio = BIO_new_mem_buf(buf, cnt);
    BIO_set_mem_eof_return(rbio, -1);

    pthread_mutex_lock(&q->mutex);
    if (!list_push(q->entries, rbio)) {
	BIO_free(rbio);
	pthread_mutex_unlock(&q->mutex);
	return 0;
    }
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

BIO *getrbio(SSL *ssl, struct gqueue *q, int timeout) {
    BIO *rbio;
    struct timeval now;
    struct timespec to;

    pthread_mutex_lock(&q->mutex);
    if (!(rbio = (BIO *)list_shift(q->entries))) {
	if (timeout) {
	    gettimeofday(&now, NULL);
	    memset(&to, 0, sizeof(struct timespec));
	    to.tv_sec = now.tv_sec + timeout;
	    pthread_cond_timedwait(&q->cond, &q->mutex, &to);
	} else
	    pthread_cond_wait(&q->cond, &q->mutex);
	rbio = (BIO *)list_shift(q->entries);
    }
    pthread_mutex_unlock(&q->mutex);
    return rbio;
}

int dtlsread(SSL *ssl, struct gqueue *q, unsigned char *buf, int num, int timeout) {
    int len, cnt;
    BIO *rbio;

    for (len = 0; len < num; len += cnt) {
	cnt = SSL_read(ssl, buf + len, num - len);
	if (cnt <= 0)
	    switch (cnt = SSL_get_error(ssl, cnt)) {
	    case SSL_ERROR_WANT_READ:
		rbio = getrbio(ssl, q, timeout);
		if (!rbio)
		    return 0;
		BIO_free(ssl->rbio);
		ssl->rbio = rbio;
		cnt = 0;
		continue;
	    case SSL_ERROR_WANT_WRITE:
		cnt = 0;
		continue;
	    case SSL_ERROR_ZERO_RETURN:
		/* remote end sent close_notify, send one back */
		SSL_shutdown(ssl);
		return -1;
	    default:
		return -1;
	    }
    }
    return num;
}

/* accept if acc == 1, else connect */
SSL *dtlsacccon(uint8_t acc, SSL_CTX *ctx, int s, struct sockaddr *addr, struct gqueue *rbios) {
    SSL *ssl;
    int i, res;
    unsigned long error;
    BIO *mem0bio, *wbio;

    ssl = SSL_new(ctx);
    if (!ssl)
	return NULL;

    mem0bio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(mem0bio, -1);
    wbio = BIO_new_dgram(s, BIO_NOCLOSE);
    i = BIO_dgram_set_peer(wbio, addr); /* i just to avoid warning */
    SSL_set_bio(ssl, mem0bio, wbio);

    for (i = 0; i < 5; i++) {
        res = acc ? SSL_accept(ssl) : SSL_connect(ssl);
        if (res > 0)
            return ssl;
        if (res == 0)
            break;
        if (SSL_get_error(ssl, res) == SSL_ERROR_WANT_READ) {
            BIO_free(ssl->rbio);
            ssl->rbio = getrbio(ssl, rbios, 5);
            if (!ssl->rbio)
                break;
        }
        while ((error = ERR_get_error()))
            debug(DBG_ERR, "dtls%st: DTLS: %s", acc ? "accep" : "connec", ERR_error_string(error, NULL));
    }

    SSL_free(ssl);
    return NULL;
}

unsigned char *raddtlsget(SSL *ssl, struct gqueue *rbios, int timeout) {
    int cnt, len;
    unsigned char buf[4], *rad;

    for (;;) {
        cnt = dtlsread(ssl, rbios, buf, 4, timeout);
        if (cnt < 1) {
            debug(DBG_DBG, cnt ? "raddtlsget: connection lost" : "raddtlsget: timeout");
            return NULL;
        }

	len = RADLEN(buf);
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "raddtlsget: malloc failed");
	    continue;
	}
	memcpy(rad, buf, 4);

	cnt = dtlsread(ssl, rbios, rad + 4, len - 4, timeout);
        if (cnt < 1) {
            debug(DBG_DBG, cnt ? "raddtlsget: connection lost" : "raddtlsget: timeout");
            free(rad);
            return NULL;
        }

        if (len >= 20)
            break;

        free(rad);
        debug(DBG_WARN, "raddtlsget: packet smaller than minimum radius size");
    }

    debug(DBG_DBG, "raddtlsget: got %d bytes", len);
    return rad;
}

void *dtlsserverwr(void *arg) {
    int cnt;
    unsigned long error;
    struct client *client = (struct client *)arg;
    struct gqueue *replyq;
    struct request *reply;

    debug(DBG_DBG, "dtlsserverwr: starting for %s", addr2string(client->addr));
    replyq = client->replyq;
    for (;;) {
	pthread_mutex_lock(&replyq->mutex);
	while (!list_first(replyq->entries)) {
	    if (client->ssl) {
		debug(DBG_DBG, "dtlsserverwr: waiting for signal");
		pthread_cond_wait(&replyq->cond, &replyq->mutex);
		debug(DBG_DBG, "dtlsserverwr: got signal");
	    }
	    if (!client->ssl) {
		/* ssl might have changed while waiting */
		pthread_mutex_unlock(&replyq->mutex);
		debug(DBG_DBG, "dtlsserverwr: exiting as requested");
		ERR_remove_state(0);
		pthread_exit(NULL);
	    }
	}
	reply = (struct request *)list_shift(replyq->entries);
	pthread_mutex_unlock(&replyq->mutex);
	cnt = SSL_write(client->ssl, reply->replybuf, RADLEN(reply->replybuf));
	if (cnt > 0)
	    debug(DBG_DBG, "dtlsserverwr: sent %d bytes, Radius packet of length %d to %s",
		  cnt, RADLEN(reply->replybuf), addr2string(client->addr));
	else
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "dtlsserverwr: SSL: %s", ERR_error_string(error, NULL));
	freerq(reply);
    }
}

void dtlsserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf;
    pthread_t dtlsserverwrth;

    debug(DBG_DBG, "dtlsserverrd: starting for %s", addr2string(client->addr));

    if (pthread_create(&dtlsserverwrth, NULL, dtlsserverwr, (void *)client)) {
	debug(DBG_ERR, "dtlsserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	buf = raddtlsget(client->ssl, client->rbios, IDLE_TIMEOUT);
	if (!buf) {
	    debug(DBG_ERR, "dtlsserverrd: connection from %s lost", addr2string(client->addr));
	    break;
	}
	debug(DBG_DBG, "dtlsserverrd: got Radius message from %s", addr2string(client->addr));
	rq = newrequest();
	if (!rq) {
	    free(buf);
	    continue;
	}
	rq->buf = buf;
	rq->from = client;
	if (!radsrv(rq)) {
	    debug(DBG_ERR, "dtlsserverrd: message authentication/validation failed, closing connection from %s", addr2string(client->addr));
	    break;
	}
    }

    /* stop writer by setting ssl to NULL and give signal in case waiting for data */
    client->ssl = NULL;

    pthread_mutex_lock(&client->replyq->mutex);
    pthread_cond_signal(&client->replyq->cond);
    pthread_mutex_unlock(&client->replyq->mutex);
    debug(DBG_DBG, "dtlsserverrd: waiting for writer to end");
    pthread_join(dtlsserverwrth, NULL);
    debug(DBG_DBG, "dtlsserverrd: reader for %s exiting", addr2string(client->addr));
}

void *dtlsservernew(void *arg) {
    struct dtlsservernewparams *params = (struct dtlsservernewparams *)arg;
    struct client *client;
    struct clsrvconf *conf;
    struct list_node *cur = NULL;
    SSL *ssl = NULL;
    X509 *cert = NULL;
    SSL_CTX *ctx = NULL;
    uint8_t delay = 60;

    debug(DBG_DBG, "dtlsservernew: starting");
    conf = find_clconf(handle, (struct sockaddr *)&params->addr, NULL);
    if (conf) {
	ctx = tlsgetctx(handle, conf->tlsconf);
	if (!ctx)
	    goto exit;
	ssl = dtlsacccon(1, ctx, params->sock, (struct sockaddr *)&params->addr, params->sesscache->rbios);
	if (!ssl)
	    goto exit;
	cert = verifytlscert(ssl);
        if (!cert)
            goto exit;
    }

    while (conf) {
	if (verifyconfcert(cert, conf)) {
	    X509_free(cert);
	    client = addclient(conf, 1);
	    if (client) {
		client->sock = params->sock;
		client->addr = addr_copy((struct sockaddr *)&params->addr);
		client->rbios = params->sesscache->rbios;
		client->ssl = ssl;
		dtlsserverrd(client);
		removeclient(client);
		delay = 0;
	    } else {
		debug(DBG_WARN, "dtlsservernew: failed to create new client instance");
	    }
	    goto exit;
	}
	conf = find_clconf(handle, (struct sockaddr *)&params->addr, &cur);
    }
    debug(DBG_WARN, "dtlsservernew: ignoring request, no matching TLS client");

    if (cert)
	X509_free(cert);

exit:
    if (ssl) {
	SSL_shutdown(ssl);
	SSL_free(ssl);
    }
    pthread_mutex_lock(&params->sesscache->mutex);
    freebios(params->sesscache->rbios);
    params->sesscache->rbios = NULL;
    gettimeofday(&params->sesscache->expiry, NULL);
    params->sesscache->expiry.tv_sec += delay;
    pthread_mutex_unlock(&params->sesscache->mutex);
    free(params);
    ERR_remove_state(0);
    pthread_exit(NULL);
    debug(DBG_DBG, "dtlsservernew: exiting");
}

void cacheexpire(struct hash *cache, struct timeval *last) {
    struct timeval now;
    struct hash_entry *he;
    struct sessioncacheentry *e;

    gettimeofday(&now, NULL);
    if (now.tv_sec - last->tv_sec < 19)
	return;

    for (he = hash_first(cache); he; he = hash_next(he)) {
	e = (struct sessioncacheentry *)he->data;
	pthread_mutex_lock(&e->mutex);
	if (!e->expiry.tv_sec || e->expiry.tv_sec > now.tv_sec) {
	    pthread_mutex_unlock(&e->mutex);
	    continue;
	}
	debug(DBG_DBG, "cacheexpire: freeing entry");
	hash_extract(cache, he->key, he->keylen);
	if (e->rbios) {
	    freebios(e->rbios);
	    e->rbios = NULL;
	}
	pthread_mutex_unlock(&e->mutex);
	pthread_mutex_destroy(&e->mutex);
    }
    last->tv_sec = now.tv_sec;
}

void *udpdtlsserverrd(void *arg) {
    int ndesc, cnt, s = *(int *)arg;
    unsigned char buf[4];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    struct dtlsservernewparams *params;
    fd_set readfds;
    struct timeval timeout, lastexpiry;
    pthread_t dtlsserverth;
    struct hash *sessioncache;
    struct sessioncacheentry *cacheentry;

    sessioncache = hash_create();
    if (!sessioncache)
	debugx(1, DBG_ERR, "udpdtlsserverrd: malloc failed");
    gettimeofday(&lastexpiry, NULL);

    for (;;) {
	FD_ZERO(&readfds);
        FD_SET(s, &readfds);
	memset(&timeout, 0, sizeof(struct timeval));
	timeout.tv_sec = 60;
	ndesc = select(s + 1, &readfds, NULL, NULL, &timeout);
	if (ndesc < 1) {
	    cacheexpire(sessioncache, &lastexpiry);
	    continue;
	}
	cnt = recvfrom(s, buf, 4, MSG_PEEK | MSG_TRUNC, (struct sockaddr *)&from, &fromlen);
	if (cnt == -1) {
	    debug(DBG_WARN, "udpdtlsserverrd: recv failed");
	    cacheexpire(sessioncache, &lastexpiry);
	    continue;
	}
	cacheentry = hash_read(sessioncache, &from, fromlen);
	if (cacheentry) {
	    debug(DBG_DBG, "udpdtlsserverrd: cache hit");
	    pthread_mutex_lock(&cacheentry->mutex);
	    if (cacheentry->rbios) {
		if (udp2bio(s, cacheentry->rbios, cnt))
		    debug(DBG_DBG, "udpdtlsserverrd: got DTLS in UDP from %s", addr2string((struct sockaddr *)&from));
	    } else
		recv(s, buf, 1, 0);
	    pthread_mutex_unlock(&cacheentry->mutex);
	    cacheexpire(sessioncache, &lastexpiry);
	    continue;
	}

	/* from new source */
	debug(DBG_DBG, "udpdtlsserverrd: cache miss");
	params = malloc(sizeof(struct dtlsservernewparams));
	if (!params) {
	    cacheexpire(sessioncache, &lastexpiry);
	    recv(s, buf, 1, 0);
	    continue;
	}
	memset(params, 0, sizeof(struct dtlsservernewparams));
	params->sesscache = malloc(sizeof(struct sessioncacheentry));
	if (!params->sesscache) {
	    free(params);
	    cacheexpire(sessioncache, &lastexpiry);
	    recv(s, buf, 1, 0);
	    continue;
	}
	memset(params->sesscache, 0, sizeof(struct sessioncacheentry));
	pthread_mutex_init(&params->sesscache->mutex, NULL);
	params->sesscache->rbios = newqueue();
	if (hash_insert(sessioncache, &from, fromlen, params->sesscache)) {
	    params->sock = s;
	    memcpy(&params->addr, &from, fromlen);

	    if (udp2bio(s, params->sesscache->rbios, cnt)) {
		debug(DBG_DBG, "udpdtlsserverrd: got DTLS in UDP from %s", addr2string((struct sockaddr *)&from));
		if (!pthread_create(&dtlsserverth, NULL, dtlsservernew, (void *)params)) {
		    pthread_detach(dtlsserverth);
		    cacheexpire(sessioncache, &lastexpiry);
		    continue;
		}
		debug(DBG_ERR, "udpdtlsserverrd: pthread_create failed");
	    }
	    hash_extract(sessioncache, &from, fromlen);
	}
	freebios(params->sesscache->rbios);
	pthread_mutex_destroy(&params->sesscache->mutex);
	free(params->sesscache);
	free(params);
	cacheexpire(sessioncache, &lastexpiry);
    }
}

int dtlsconnect(struct server *server, struct timeval *when, int timeout, char *text) {
    struct timeval now;
    time_t elapsed;
    X509 *cert;
    SSL_CTX *ctx = NULL;
    struct hostportres *hp;

    debug(DBG_DBG, "dtlsconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);
    if (when && memcmp(&server->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	debug(DBG_DBG, "dtlsconnect(%s): seems already reconnected", text);
	pthread_mutex_unlock(&server->lock);
	return 1;
    }

    hp = (struct hostportres *)list_first(server->conf->hostports)->data;
    for (;;) {
	gettimeofday(&now, NULL);
	elapsed = now.tv_sec - server->lastconnecttry.tv_sec;

	if (timeout && server->lastconnecttry.tv_sec && elapsed > timeout) {
	    debug(DBG_DBG, "dtlsconnect: timeout");
	    SSL_free(server->ssl);
	    server->ssl = NULL;
	    pthread_mutex_unlock(&server->lock);
	    return 0;
	}

	if (server->connectionok) {
	    server->connectionok = 0;
	    sleep(2);
	} else if (elapsed < 1)
	    sleep(2);
	else if (elapsed < 60) {
	    debug(DBG_INFO, "dtlsconnect: sleeping %lds", elapsed);
	    sleep(elapsed);
	} else if (elapsed < 100000) {
	    debug(DBG_INFO, "dtlsconnect: sleeping %ds", 60);
	    sleep(60);
	} else
	    server->lastconnecttry.tv_sec = now.tv_sec;  /* no sleep at startup */
	debug(DBG_WARN, "dtlsconnect: trying to open DTLS connection to %s port %s", hp->host, hp->port);

	SSL_free(server->ssl);
	server->ssl = NULL;
	ctx = tlsgetctx(handle, server->conf->tlsconf);
	if (!ctx)
	    continue;
	server->ssl = dtlsacccon(0, ctx, server->sock, hp->addrinfo->ai_addr, server->rbios);
	if (!server->ssl)
	    continue;
	debug(DBG_DBG, "dtlsconnect: DTLS: ok");

	cert = verifytlscert(server->ssl);
	if (!cert)
	    continue;

	if (verifyconfcert(cert, server->conf))
	    break;
	X509_free(cert);
    }
    X509_free(cert);
    debug(DBG_WARN, "dtlsconnect: DTLS connection to %s port %s up", hp->host, hp->port);
    server->connectionok = 1;
    gettimeofday(&server->lastconnecttry, NULL);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

int clientradputdtls(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct clsrvconf *conf = server->conf;

    if (!server->connectionok)
	return 0;
    len = RADLEN(rad);
    if ((cnt = SSL_write(server->ssl, rad, len)) <= 0) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "clientradputdtls: DTLS: %s", ERR_error_string(error, NULL));
	return 0;
    }
    debug(DBG_DBG, "clientradputdtls: Sent %d bytes, Radius packet of length %d to DTLS peer %s", cnt, len, conf->name);
    return 1;
}

/* reads UDP containing DTLS and passes it on to dtlsclientrd */
void *udpdtlsclientrd(void *arg) {
    int cnt, s = *(int *)arg;
    unsigned char buf[4];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    struct clsrvconf *conf;
    fd_set readfds;

    for (;;) {
	FD_ZERO(&readfds);
        FD_SET(s, &readfds);
	if (select(s + 1, &readfds, NULL, NULL, NULL) < 1)
	    continue;
	cnt = recvfrom(s, buf, 4, MSG_PEEK | MSG_TRUNC, (struct sockaddr *)&from, &fromlen);
	if (cnt == -1) {
	    debug(DBG_WARN, "udpdtlsclientrd: recv failed");
	    continue;
	}

	conf = find_srvconf(handle, (struct sockaddr *)&from, NULL);
	if (!conf) {
	    debug(DBG_WARN, "udpdtlsclientrd: got packet from wrong or unknown DTLS peer %s, ignoring", addr2string((struct sockaddr *)&from));
	    recv(s, buf, 4, 0);
	    continue;
	}
	if (udp2bio(s, conf->servers->rbios, cnt))
	    debug(DBG_DBG, "radudpget: got DTLS in UDP from %s", addr2string((struct sockaddr *)&from));
    }
}

void *dtlsclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    struct timeval lastconnecttry;
    int secs;

    for (;;) {
	/* yes, lastconnecttry is really necessary */
	lastconnecttry = server->lastconnecttry;
	for (secs = 0; !(buf = raddtlsget(server->ssl, server->rbios, 10)) && !server->lostrqs && secs < IDLE_TIMEOUT; secs += 10);
	if (!buf) {
	    dtlsconnect(server, &lastconnecttry, 0, "dtlsclientrd");
	    continue;
	}
	replyh(server, buf);
    }
    ERR_remove_state(0);
    server->clientrdgone = 1;
    return NULL;
}

void addserverextradtls(struct clsrvconf *conf) {
    switch (((struct hostportres *)list_first(conf->hostports)->data)->addrinfo->ai_family) {
    case AF_INET:
	if (client4_sock < 0) {
	    client4_sock = bindtoaddr(srcres, AF_INET, 0, 1);
	    if (client4_sock < 0)
		debugx(1, DBG_ERR, "addserver: failed to create client socket for server %s", conf->name);
	}
	conf->servers->sock = client4_sock;
	break;
    case AF_INET6:
	if (client6_sock < 0) {
	    client6_sock = bindtoaddr(srcres, AF_INET6, 0, 1);
	    if (client6_sock < 0)
		debugx(1, DBG_ERR, "addserver: failed to create client socket for server %s", conf->name);
	}
	conf->servers->sock = client6_sock;
	break;
    default:
	debugx(1, DBG_ERR, "addserver: unsupported address family");
    }
}

void initextradtls() {
    pthread_t cl4th, cl6th;

    if (srcres) {
	freeaddrinfo(srcres);
	srcres = NULL;
    }

    if (client4_sock >= 0)
	if (pthread_create(&cl4th, NULL, udpdtlsclientrd, (void *)&client4_sock))
	    debugx(1, DBG_ERR, "pthread_create failed");
    if (client6_sock >= 0)
	if (pthread_create(&cl6th, NULL, udpdtlsclientrd, (void *)&client6_sock))
	    debugx(1, DBG_ERR, "pthread_create failed");
}
#else
const struct protodefs *dtlsinit(uint8_t h) {
    return NULL;
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
