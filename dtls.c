/*
 * Copyright (C) 2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
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
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "debug.h"
#include "list.h"
#include "util.h"
#include "radsecproxy.h"
#include "dtls.h"

int udp2bio(int s, struct queue *q, int cnt) {
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

BIO *getrbio(SSL *ssl, struct queue *q, int timeout) {
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

void *udpdtlsserverrd(void *arg) {
    int cnt, s = *(int *)arg;
    unsigned char buf[4];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    struct clsrvconf *conf;
    struct list_node *node;
    struct client *client;
    fd_set readfds;
    pthread_t dtlsserverth;

    for (;;) {
	FD_ZERO(&readfds);
        FD_SET(s, &readfds);
	if (select(s + 1, &readfds, NULL, NULL, NULL) < 1)
	    continue;
	cnt = recvfrom(s, buf, 4, MSG_PEEK | MSG_TRUNC, (struct sockaddr *)&from, &fromlen);
	if (cnt == -1) {
	    debug(DBG_WARN, "udpdtlsserverrd: recv failed");
	    continue;
	}
	conf = find_clconf(RAD_DTLS, (struct sockaddr *)&from, NULL);
	if (!conf) {
	    debug(DBG_WARN, "udpdtlsserverrd: got packet from wrong or unknown DTLS peer %s, ignoring", addr2string((struct sockaddr *)&from, fromlen));
	    recv(s, buf, 4, 0);
	    continue;
	}
	
	node = list_first(conf->clients);
	if (node)
	    client = (struct client *)node->data;
	else {
	    client = addclient(conf);
	    if (!client) {
		recv(s, buf, 4, 0);
		continue;
	    }
	    client->sock = s;
	    memcpy(&client->addr, &from, fromlen);
	    if (pthread_create(&dtlsserverth, NULL, dtlsservernew, (void *)client)) {
		debug(DBG_ERR, "udpdtlsserverrd: pthread_create failed");
		removeclient(client);
		recv(s, buf, 4, 0);
		continue;
	    }
	    pthread_detach(dtlsserverth);
	}
	if (udp2bio(s, client->rbios, cnt))
	    debug(DBG_DBG, "udpdtlsserverrd: got DTLS in UDP from %s", addr2string((struct sockaddr *)&from, fromlen));
    }
}

void *dtlsserverwr(void *arg) {
    int cnt;
    unsigned long error;
    struct client *client = (struct client *)arg;
    struct queue *replyq;
    struct reply *reply;
    
    debug(DBG_DBG, "dtlsserverwr: starting for %s", client->conf->host);
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
	reply = (struct reply *)list_shift(replyq->entries);
	pthread_mutex_unlock(&replyq->mutex);
	cnt = SSL_write(client->ssl, reply->buf, RADLEN(reply->buf));
	if (cnt > 0)
	    debug(DBG_DBG, "dtlsserverwr: sent %d bytes, Radius packet of length %d",
		  cnt, RADLEN(reply->buf));
	else
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "dtlsserverwr: SSL: %s", ERR_error_string(error, NULL));
	free(reply->buf);
	free(reply);
    }
}

int dtlsread(SSL *ssl, struct queue *q, unsigned char *buf, int num) {
    int len, cnt;

    for (len = 0; len < num; len += cnt) {
	cnt = SSL_read(ssl, buf + len, num - len);
	if (cnt <= 0)
	    switch (cnt = SSL_get_error(ssl, cnt)) {
	    case SSL_ERROR_WANT_READ:
		BIO_free(ssl->rbio);		
		ssl->rbio = getrbio(ssl, q, 0);
		if (!ssl->rbio)
		    return -1;
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

unsigned char *raddtlsget(SSL *ssl, struct queue *rbios) {
    int cnt, len;
    unsigned char buf[4], *rad;

    for (;;) {
        cnt = dtlsread(ssl, rbios, buf, 4);
        if (cnt < 1) {
            debug(DBG_DBG, "raddtlsget: connection lost");
            return NULL;
        }

	len = RADLEN(buf);
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "raddtlsget: malloc failed");
	    continue;
	}
	memcpy(rad, buf, 4);
	
	cnt = dtlsread(ssl, rbios, rad + 4, len - 4);
        if (cnt < 1) {
            debug(DBG_DBG, "raddtlsget: connection lost");
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

void dtlsserverrd(struct client *client) {
    struct request rq;
    pthread_t dtlsserverwrth;
    
    debug(DBG_DBG, "dtlsserverrd: starting for %s", client->conf->host);

    if (pthread_create(&dtlsserverwrth, NULL, dtlsserverwr, (void *)client)) {
	debug(DBG_ERR, "dtlsserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	memset(&rq, 0, sizeof(struct request));
	rq.buf = raddtlsget(client->ssl, client->rbios);
	if (!rq.buf) {
	    debug(DBG_ERR, "dtlsserverrd: connection from %s lost", client->conf->host);
	    break;
	}
	debug(DBG_DBG, "dtlsserverrd: got Radius message from %s", client->conf->host);
	rq.from = client;
	if (!radsrv(&rq)) {
	    debug(DBG_ERR, "dtlsserverrd: message authentication/validation failed, closing connection from %s", client->conf->host);
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
    removeclientrqs(client);
    debug(DBG_DBG, "dtlsserverrd: reader for %s exiting", client->conf->host);
}

/* accept if acc == 1, else connect */
SSL *dtlsacccon(uint8_t acc, SSL_CTX *ctx, int s, struct sockaddr *addr, struct queue *rbios) {
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
    BIO_dgram_set_peer(wbio, addr);
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

void *dtlsservernew(void *arg) {
    struct client *client = (struct client *)arg;
    X509 *cert = NULL;

    client->ssl = dtlsacccon(1, client->conf->ssl_ctx, client->sock, (struct sockaddr *)&client->addr, client->rbios);
    if (!client->ssl)
	goto exit;
    cert = verifytlscert(client->ssl);
    if (!cert)
	goto exit;
    if (verifyconfcert(cert, client->conf)) {
	X509_free(cert);
	dtlsserverrd(client);
	removeclient(client);
    } else
	debug(DBG_WARN, "dtlsservernew: ignoring request, certificate validation failed");
    if (cert)
	X509_free(cert);

 exit:
    SSL_free(client->ssl);
    ERR_remove_state(0);
    pthread_exit(NULL);
}

int dtlsconnect(struct server *server, struct timeval *when, int timeout, char *text) {
    struct timeval now;
    time_t elapsed;
    X509 *cert;
    
    debug(DBG_DBG, "dtlsconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);
    if (when && memcmp(&server->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	debug(DBG_DBG, "dtlsconnect(%s): seems already reconnected", text);
	pthread_mutex_unlock(&server->lock);
	return 1;
    }

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
	debug(DBG_WARN, "dtlsconnect: trying to open DTLS connection to %s port %s", server->conf->host, server->conf->port);

	SSL_free(server->ssl);
	server->ssl = dtlsacccon(0, server->conf->ssl_ctx, server->sock, server->conf->addrinfo->ai_addr, server->rbios);
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
    debug(DBG_WARN, "dtlsconnect: DTLS connection to %s port %s up", server->conf->host, server->conf->port);
    gettimeofday(&server->lastconnecttry, NULL);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

int clientradputdtls(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct clsrvconf *conf = server->conf;
    
    len = RADLEN(rad);
    while ((cnt = SSL_write(server->ssl, rad, len)) <= 0) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "clientradputdtls: DTLS: %s", ERR_error_string(error, NULL));
    }
    debug(DBG_DBG, "clientradputdtls: Sent %d bytes, Radius packet of length %d to DTLS peer %s", cnt, len, conf->host);
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
	
	conf = find_srvconf(RAD_DTLS, (struct sockaddr *)&from, NULL);
	if (!conf) {
	    debug(DBG_WARN, "udpdtlsclientrd: got packet from wrong or unknown DTLS peer %s, ignoring", addr2string((struct sockaddr *)&from, fromlen));
	    recv(s, buf, 4, 0);
	    continue;
	}
	if (udp2bio(s, conf->servers->rbios, cnt))
	    debug(DBG_DBG, "radudpget: got DTLS in UDP from %s", addr2string((struct sockaddr *)&from, fromlen));
    }
}

void *dtlsclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    struct timeval lastconnecttry;
    
    for (;;) {
	/* yes, lastconnecttry is really necessary */
	lastconnecttry = server->lastconnecttry;
	buf = raddtlsget(server->ssl, server->rbios);
	if (!buf) {
	    dtlsconnect(server, &lastconnecttry, 0, "dtlsclientrd");
	    continue;
	}

	if (!replyh(server, buf))
	    free(buf);
    }
}

