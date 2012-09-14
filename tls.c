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
#include "radsecproxy.h"
#include "hostport.h"

#ifdef RADPROT_TLS
#include "debug.h"
#include "util.h"

static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs();
void *tlslistener(void *arg);
int tlsconnect(struct server *server, struct timeval *when, int timeout, char *text);
void *tlsclientrd(void *arg);
int clientradputtls(struct server *server, unsigned char *rad);
void tlssetsrcres();

static const struct protodefs protodefs = {
    "tls",
    "radsec", /* secretdefault */
    SOCK_STREAM, /* socktype */
    "2083", /* portdefault */
    0, /* retrycountdefault */
    0, /* retrycountmax */
    REQUEST_RETRY_INTERVAL * REQUEST_RETRY_COUNT, /* retryintervaldefault */
    60, /* retryintervalmax */
    DUPLICATE_INTERVAL, /* duplicateintervaldefault */
    setprotoopts, /* setprotoopts */
    getlistenerargs, /* getlistenerargs */
    tlslistener, /* listener */
    tlsconnect, /* connecter */
    tlsclientrd, /* clientconnreader */
    clientradputtls, /* clientradput */
    NULL, /* addclient */
    NULL, /* addserverextra */
    tlssetsrcres, /* setsrcres */
    NULL /* initextra */
};

static struct addrinfo *srcres = NULL;
static uint8_t handle;
static struct commonprotoopts *protoopts = NULL;

const struct protodefs *tlsinit(uint8_t h) {
    handle = h;
    return &protodefs;
}

static void setprotoopts(struct commonprotoopts *opts) {
    protoopts = opts;
}

static char **getlistenerargs() {
    return protoopts ? protoopts->listenargs : NULL;
}

void tlssetsrcres() {
    if (!srcres)
	srcres =
            resolvepassiveaddrinfo(protoopts ? protoopts->sourcearg : NULL,
                                   AF_UNSPEC, NULL, protodefs.socktype);
}

int tlsconnect(struct server *server, struct timeval *when, int timeout, char *text) {
    struct timeval now;
    time_t elapsed;
    X509 *cert;
    SSL_CTX *ctx = NULL;
    unsigned long error;

    debug(DBG_DBG, "tlsconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);
    if (when && memcmp(&server->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	debug(DBG_DBG, "tlsconnect(%s): seems already reconnected", text);
	pthread_mutex_unlock(&server->lock);
	return 1;
    }

    for (;;) {
	gettimeofday(&now, NULL);
	elapsed = now.tv_sec - server->lastconnecttry.tv_sec;
	if (timeout && server->lastconnecttry.tv_sec && elapsed > timeout) {
	    debug(DBG_DBG, "tlsconnect: timeout");
	    if (server->sock >= 0)
		close(server->sock);
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
	    debug(DBG_INFO, "tlsconnect: sleeping %lds", elapsed);
	    sleep(elapsed);
	} else if (elapsed < 100000) {
	    debug(DBG_INFO, "tlsconnect: sleeping %ds", 60);
	    sleep(60);
	} else
	    server->lastconnecttry.tv_sec = now.tv_sec;  /* no sleep at startup */

	if (server->sock >= 0)
	    close(server->sock);
	if ((server->sock = connecttcphostlist(server->conf->hostports, srcres)) < 0)
	    continue;

	SSL_free(server->ssl);
	server->ssl = NULL;
	ctx = tlsgetctx(handle, server->conf->tlsconf);
	if (!ctx)
	    continue;
	server->ssl = SSL_new(ctx);
	if (!server->ssl)
	    continue;

	SSL_set_fd(server->ssl, server->sock);
	if (SSL_connect(server->ssl) <= 0) {
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "tlsconnect: TLS: %s", ERR_error_string(error, NULL));
	    continue;
	}
	cert = verifytlscert(server->ssl);
	if (!cert)
	    continue;
	if (verifyconfcert(cert, server->conf)) {
	    X509_free(cert);
	    break;
	}
	X509_free(cert);
    }
    debug(DBG_WARN, "tlsconnect: TLS connection to %s up", server->conf->name);
    server->connectionok = 1;
    gettimeofday(&server->lastconnecttry, NULL);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

/* timeout in seconds, 0 means no timeout (blocking), returns when num bytes have been read, or timeout */
/* returns 0 on timeout, -1 on error and num if ok */
int sslreadtimeout(SSL *ssl, unsigned char *buf, int num, int timeout) {
    int s, ndesc, cnt, len;
    fd_set readfds, writefds;
    struct timeval timer;

    s = SSL_get_fd(ssl);
    if (s < 0)
	return -1;
    /* make socket non-blocking? */
    for (len = 0; len < num; len += cnt) {
	FD_ZERO(&readfds);
	FD_SET(s, &readfds);
	writefds = readfds;
	if (timeout) {
	    timer.tv_sec = timeout;
	    timer.tv_usec = 0;
	}
	ndesc = select(s + 1, &readfds, &writefds, NULL, timeout ? &timer : NULL);
	if (ndesc < 1)
	    return ndesc;

	cnt = SSL_read(ssl, buf + len, num - len);
	if (cnt <= 0)
	    switch (SSL_get_error(ssl, cnt)) {
	    case SSL_ERROR_WANT_READ:
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

/* timeout in seconds, 0 means no timeout (blocking) */
unsigned char *radtlsget(SSL *ssl, int timeout) {
    int cnt, len;
    unsigned char buf[4], *rad;

    for (;;) {
	cnt = sslreadtimeout(ssl, buf, 4, timeout);
	if (cnt < 1) {
	    debug(DBG_DBG, cnt ? "radtlsget: connection lost" : "radtlsget: timeout");
	    return NULL;
	}

	len = RADLEN(buf);
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "radtlsget: malloc failed");
	    continue;
	}
	memcpy(rad, buf, 4);

	cnt = sslreadtimeout(ssl, rad + 4, len - 4, timeout);
	if (cnt < 1) {
	    debug(DBG_DBG, cnt ? "radtlsget: connection lost" : "radtlsget: timeout");
	    free(rad);
	    return NULL;
	}

	if (len >= 20)
	    break;

	free(rad);
	debug(DBG_WARN, "radtlsget: packet smaller than minimum radius size");
    }

    debug(DBG_DBG, "radtlsget: got %d bytes", len);
    return rad;
}

int clientradputtls(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct clsrvconf *conf = server->conf;

    if (!server->connectionok)
	return 0;
    len = RADLEN(rad);
    if ((cnt = SSL_write(server->ssl, rad, len)) <= 0) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "clientradputtls: TLS: %s", ERR_error_string(error, NULL));
	return 0;
    }

    debug(DBG_DBG, "clientradputtls: Sent %d bytes, Radius packet of length %d to TLS peer %s", cnt, len, conf->name);
    return 1;
}

void *tlsclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    struct timeval now, lastconnecttry;

    for (;;) {
	/* yes, lastconnecttry is really necessary */
	lastconnecttry = server->lastconnecttry;
	buf = radtlsget(server->ssl, server->dynamiclookuparg ? IDLE_TIMEOUT : 0);
	if (!buf) {
	    if (server->dynamiclookuparg)
		break;
	    tlsconnect(server, &lastconnecttry, 0, "tlsclientrd");
	    continue;
	}

	replyh(server, buf);

	if (server->dynamiclookuparg) {
	    gettimeofday(&now, NULL);
	    if (now.tv_sec - server->lastreply.tv_sec > IDLE_TIMEOUT) {
		debug(DBG_INFO, "tlsclientrd: idle timeout for %s", server->conf->name);
		break;
	    }
	}
    }
    ERR_remove_state(0);
    server->clientrdgone = 1;
    return NULL;
}

void *tlsserverwr(void *arg) {
    int cnt;
    unsigned long error;
    struct client *client = (struct client *)arg;
    struct gqueue *replyq;
    struct request *reply;

    debug(DBG_DBG, "tlsserverwr: starting for %s", addr2string(client->addr));
    replyq = client->replyq;
    for (;;) {
	pthread_mutex_lock(&replyq->mutex);
	while (!list_first(replyq->entries)) {
	    if (client->ssl) {
		debug(DBG_DBG, "tlsserverwr: waiting for signal");
		pthread_cond_wait(&replyq->cond, &replyq->mutex);
		debug(DBG_DBG, "tlsserverwr: got signal");
	    }
	    if (!client->ssl) {
		/* ssl might have changed while waiting */
		pthread_mutex_unlock(&replyq->mutex);
		debug(DBG_DBG, "tlsserverwr: exiting as requested");
		ERR_remove_state(0);
		pthread_exit(NULL);
	    }
	}
	reply = (struct request *)list_shift(replyq->entries);
	pthread_mutex_unlock(&replyq->mutex);
	cnt = SSL_write(client->ssl, reply->replybuf, RADLEN(reply->replybuf));
	if (cnt > 0)
	    debug(DBG_DBG, "tlsserverwr: sent %d bytes, Radius packet of length %d to %s",
		  cnt, RADLEN(reply->replybuf), addr2string(client->addr));
	else
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "tlsserverwr: SSL: %s", ERR_error_string(error, NULL));
	freerq(reply);
    }
}

void tlsserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf;
    pthread_t tlsserverwrth;

    debug(DBG_DBG, "tlsserverrd: starting for %s", addr2string(client->addr));

    if (pthread_create(&tlsserverwrth, NULL, tlsserverwr, (void *)client)) {
	debug(DBG_ERR, "tlsserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	buf = radtlsget(client->ssl, 0);
	if (!buf) {
	    debug(DBG_ERR, "tlsserverrd: connection from %s lost", addr2string(client->addr));
	    break;
	}
	debug(DBG_DBG, "tlsserverrd: got Radius message from %s", addr2string(client->addr));
	rq = newrequest();
	if (!rq) {
	    free(buf);
	    continue;
	}
	rq->buf = buf;
	rq->from = client;
	if (!radsrv(rq)) {
	    debug(DBG_ERR, "tlsserverrd: message authentication/validation failed, closing connection from %s", addr2string(client->addr));
	    break;
	}
    }

    /* stop writer by setting ssl to NULL and give signal in case waiting for data */
    client->ssl = NULL;
    pthread_mutex_lock(&client->replyq->mutex);
    pthread_cond_signal(&client->replyq->cond);
    pthread_mutex_unlock(&client->replyq->mutex);
    debug(DBG_DBG, "tlsserverrd: waiting for writer to end");
    pthread_join(tlsserverwrth, NULL);
    debug(DBG_DBG, "tlsserverrd: reader for %s exiting", addr2string(client->addr));
}

void *tlsservernew(void *arg) {
    int s;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    struct clsrvconf *conf;
    struct list_node *cur = NULL;
    SSL *ssl = NULL;
    X509 *cert = NULL;
    SSL_CTX *ctx = NULL;
    unsigned long error;
    struct client *client;
    struct tls *accepted_tls = NULL;

    s = *(int *)arg;
    if (getpeername(s, (struct sockaddr *)&from, &fromlen)) {
	debug(DBG_DBG, "tlsservernew: getpeername failed, exiting");
	goto exit;
    }
    debug(DBG_WARN, "tlsservernew: incoming TLS connection from %s", addr2string((struct sockaddr *)&from));

    conf = find_clconf(handle, (struct sockaddr *)&from, &cur);
    if (conf) {
	ctx = tlsgetctx(handle, conf->tlsconf);
	if (!ctx)
	    goto exit;
	ssl = SSL_new(ctx);
	if (!ssl)
	    goto exit;
	SSL_set_fd(ssl, s);

	if (SSL_accept(ssl) <= 0) {
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "tlsservernew: SSL: %s", ERR_error_string(error, NULL));
	    debug(DBG_ERR, "tlsservernew: SSL_accept failed");
	    goto exit;
	}
	cert = verifytlscert(ssl);
	if (!cert)
	    goto exit;
        accepted_tls = conf->tlsconf;
    }

    while (conf) {
        if (accepted_tls == conf->tlsconf && verifyconfcert(cert, conf)) {
            X509_free(cert);
            client = addclient(conf, 1);
            if (client) {
                client->ssl = ssl;
                client->addr = addr_copy((struct sockaddr *)&from);
                tlsserverrd(client);
                removeclient(client);
            } else
                debug(DBG_WARN, "tlsservernew: failed to create new client instance");
            goto exit;
        }
        conf = find_clconf(handle, (struct sockaddr *)&from, &cur);
    }
    debug(DBG_WARN, "tlsservernew: ignoring request, no matching TLS client");
    if (cert)
	X509_free(cert);

exit:
    if (ssl) {
	SSL_shutdown(ssl);
	SSL_free(ssl);
    }
    ERR_remove_state(0);
    shutdown(s, SHUT_RDWR);
    close(s);
    pthread_exit(NULL);
}

void *tlslistener(void *arg) {
    pthread_t tlsserverth;
    int s, *sp = (int *)arg;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);

    listen(*sp, 0);

    for (;;) {
	s = accept(*sp, (struct sockaddr *)&from, &fromlen);
	if (s < 0) {
	    debug(DBG_WARN, "accept failed");
	    continue;
	}
	if (pthread_create(&tlsserverth, NULL, tlsservernew, (void *)&s)) {
	    debug(DBG_ERR, "tlslistener: pthread_create failed");
	    shutdown(s, SHUT_RDWR);
	    close(s);
	    continue;
	}
	pthread_detach(tlsserverth);
    }
    free(sp);
    return NULL;
}
#else
const struct protodefs *tlsinit(uint8_t h) {
    return NULL;
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
