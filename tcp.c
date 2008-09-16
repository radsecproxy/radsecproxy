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
#include "debug.h"
#include "list.h"
#include "util.h"
#include "radsecproxy.h"
#include "tcp.h"

int tcpconnect(struct server *server, struct timeval *when, int timeout, char *text) {
    struct timeval now;
    time_t elapsed;
    
    debug(DBG_DBG, "tcpconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);
    if (when && memcmp(&server->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	debug(DBG_DBG, "tcpconnect(%s): seems already reconnected", text);
	pthread_mutex_unlock(&server->lock);
	return 1;
    }

    for (;;) {
	gettimeofday(&now, NULL);
	elapsed = now.tv_sec - server->lastconnecttry.tv_sec;
	if (timeout && server->lastconnecttry.tv_sec && elapsed > timeout) {
	    debug(DBG_DBG, "tcpconnect: timeout");
	    if (server->sock >= 0)
		close(server->sock);
	    pthread_mutex_unlock(&server->lock);
	    return 0;
	}
	if (server->connectionok) {
	    server->connectionok = 0;
	    sleep(2);
	} else if (elapsed < 1)
	    sleep(2);
	else if (elapsed < 60) {
	    debug(DBG_INFO, "tcpconnect: sleeping %lds", elapsed);
	    sleep(elapsed);
	} else if (elapsed < 100000) {
	    debug(DBG_INFO, "tcpconnect: sleeping %ds", 60);
	    sleep(60);
	} else
	    server->lastconnecttry.tv_sec = now.tv_sec;  /* no sleep at startup */
	debug(DBG_WARN, "tcpconnect: trying to open TCP connection to %s port %s", server->conf->host, server->conf->port);
	if (server->sock >= 0)
	    close(server->sock);
	if ((server->sock = connecttcp(server->conf->addrinfo, getsrcprotores(RAD_TCP))) >= 0)
	    break;
	debug(DBG_ERR, "tcpconnect: connecttcp failed");
    }
    debug(DBG_WARN, "tcpconnect: TCP connection to %s port %s up", server->conf->host, server->conf->port);
    gettimeofday(&server->lastconnecttry, NULL);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

/* timeout in seconds, 0 means no timeout (blocking), returns when num bytes have been read, or timeout */
/* returns 0 on timeout, -1 on error and num if ok */
int tcpreadtimeout(int s, unsigned char *buf, int num, int timeout) {
    int ndesc, cnt, len;
    fd_set readfds, writefds;
    struct timeval timer;
    
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

	cnt = read(s, buf + len, num - len);
	if (cnt <= 0)
	    return -1;
    }
    return num;
}

/* timeout in seconds, 0 means no timeout (blocking) */
unsigned char *radtcpget(int s, int timeout) {
    int cnt, len;
    unsigned char buf[4], *rad;

    for (;;) {
	cnt = tcpreadtimeout(s, buf, 4, timeout);
	if (cnt < 1) {
	    debug(DBG_DBG, cnt ? "radtcpget: connection lost" : "radtcpget: timeout");
	    return NULL;
	}

	len = RADLEN(buf);
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "radtcpget: malloc failed");
	    continue;
	}
	memcpy(rad, buf, 4);
	
	cnt = tcpreadtimeout(s, rad + 4, len - 4, timeout);
	if (cnt < 1) {
	    debug(DBG_DBG, cnt ? "radtcpget: connection lost" : "radtcpget: timeout");
	    free(rad);
	    return NULL;
	}
	
	if (len >= 20)
	    break;
	
	free(rad);
	debug(DBG_WARN, "radtcpget: packet smaller than minimum radius size");
    }
    
    debug(DBG_DBG, "radtcpget: got %d bytes", len);
    return rad;
}

int clientradputtcp(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    struct timeval lastconnecttry;
    struct clsrvconf *conf = server->conf;
    
    len = RADLEN(rad);
    lastconnecttry = server->lastconnecttry;
    while ((cnt = write(server->sock, rad, len)) <= 0) {
	debug(DBG_ERR, "clientradputtcp: write error");
	tcpconnect(server, &lastconnecttry, 0, "clientradputtcp");
	lastconnecttry = server->lastconnecttry;
    }

    server->connectionok = 1;
    debug(DBG_DBG, "clientradputtcp: Sent %d bytes, Radius packet of length %d to TCP peer %s", cnt, len, conf->host);
    return 1;
}

void *tcpclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    struct timeval lastconnecttry;
    
    for (;;) {
	/* yes, lastconnecttry is really necessary */
	lastconnecttry = server->lastconnecttry;
	buf = radtcpget(server->sock, 0);
	if (!buf) {
	    tcpconnect(server, &lastconnecttry, 0, "tcpclientrd");
	    continue;
	}

	replyh(server, buf);
    }
    server->clientrdgone = 1;
    return NULL;
}

void *tcpserverwr(void *arg) {
    int cnt;
    struct client *client = (struct client *)arg;
    struct queue *replyq;
    struct reply *reply;
    
    debug(DBG_DBG, "tcpserverwr: starting for %s", client->conf->host);
    replyq = client->replyq;
    for (;;) {
	pthread_mutex_lock(&replyq->mutex);
	while (!list_first(replyq->entries)) {
	    if (client->sock >= 0) {	    
		debug(DBG_DBG, "tcpserverwr: waiting for signal");
		pthread_cond_wait(&replyq->cond, &replyq->mutex);
		debug(DBG_DBG, "tcpserverwr: got signal");
	    }
	    if (client->sock < 0) {
		/* s might have changed while waiting */
		pthread_mutex_unlock(&replyq->mutex);
		debug(DBG_DBG, "tcpserverwr: exiting as requested");
		pthread_exit(NULL);
	    }
	}
	reply = (struct reply *)list_shift(replyq->entries);
	pthread_mutex_unlock(&replyq->mutex);
	cnt = write(client->sock, reply->buf, RADLEN(reply->buf));
	if (cnt > 0)
	    debug(DBG_DBG, "tcpserverwr: sent %d bytes, Radius packet of length %d",
		  cnt, RADLEN(reply->buf));
	else
	    debug(DBG_ERR, "tcpserverwr: write error for %s", client->conf->host);
	free(reply->buf);
	free(reply);
    }
}

void tcpserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf;
    pthread_t tcpserverwrth;
    
    debug(DBG_DBG, "tcpserverrd: starting for %s", client->conf->host);
    
    if (pthread_create(&tcpserverwrth, NULL, tcpserverwr, (void *)client)) {
	debug(DBG_ERR, "tcpserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	buf = radtcpget(client->sock, 0);
	if (!buf) {
	    debug(DBG_ERR, "tcpserverrd: connection from %s lost", client->conf->host);
	    break;
	}
	debug(DBG_DBG, "tcpserverrd: got Radius message from %s", client->conf->host);
	rq = newrequest();
	if (!rq) {
	    free(buf);
	    continue;
	}
	rq->buf = buf;
	rq->from = client;
	if (!radsrv(rq)) {
	    debug(DBG_ERR, "tcpserverrd: message authentication/validation failed, closing connection from %s", client->conf->host);
	    break;
	}
    }

    /* stop writer by setting s to -1 and give signal in case waiting for data */
    client->sock = -1;
    pthread_mutex_lock(&client->replyq->mutex);
    pthread_cond_signal(&client->replyq->cond);
    pthread_mutex_unlock(&client->replyq->mutex);
    debug(DBG_DBG, "tcpserverrd: waiting for writer to end");
    pthread_join(tcpserverwrth, NULL);
    removeclientrqs(client);
    debug(DBG_DBG, "tcpserverrd: reader for %s exiting", client->conf->host);
}

void *tcpservernew(void *arg) {
    int s;
    struct sockaddr_storage from;
    size_t fromlen = sizeof(from);
    struct clsrvconf *conf;
    struct client *client;

    s = *(int *)arg;
    if (getpeername(s, (struct sockaddr *)&from, &fromlen)) {
	debug(DBG_DBG, "tcpservernew: getpeername failed, exiting");
	goto exit;
    }
    debug(DBG_WARN, "tcpservernew: incoming TCP connection from %s", addr2string((struct sockaddr *)&from, fromlen));

    conf = find_clconf(RAD_TCP, (struct sockaddr *)&from, NULL);
    if (conf) {
	client = addclient(conf, 1);
	if (client) {
	    client->sock = s;
	    tcpserverrd(client);
	    removeclient(client);
	} else
	    debug(DBG_WARN, "tcpservernew: failed to create new client instance");
    } else
	debug(DBG_WARN, "tcpservernew: ignoring request, no matching TCP client");

 exit:
    shutdown(s, SHUT_RDWR);
    close(s);
    pthread_exit(NULL);
}

void *tcplistener(void *arg) {
    pthread_t tcpserverth;
    int s, *sp = (int *)arg;
    struct sockaddr_storage from;
    size_t fromlen = sizeof(from);

    listen(*sp, 0);

    for (;;) {
	s = accept(*sp, (struct sockaddr *)&from, &fromlen);
	if (s < 0) {
	    debug(DBG_WARN, "accept failed");
	    continue;
	}
	if (pthread_create(&tcpserverth, NULL, tcpservernew, (void *)&s)) {
	    debug(DBG_ERR, "tcplistener: pthread_create failed");
	    shutdown(s, SHUT_RDWR);
	    close(s);
	    continue;
	}
	pthread_detach(tcpserverth);
    }
    free(sp);
    return NULL;
}
