/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
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
#include "tls.h"

static int client4_sock = -1;
static int client6_sock = -1;
static struct queue *server_replyq = NULL;

/* exactly one of client and server must be non-NULL */
/* return who we received from in *client or *server */
/* return from in sa if not NULL */
unsigned char *radudpget(int s, struct client **client, struct server **server, uint16_t *port) {
    int cnt, len;
    unsigned char buf[4], *rad = NULL;
    struct sockaddr_storage from;
    struct sockaddr *fromcopy;
    socklen_t fromlen = sizeof(from);
    struct clsrvconf *p;
    struct list_node *node;
    fd_set readfds;
    struct client *c = NULL;
    
    for (;;) {
	if (rad) {
	    free(rad);
	    rad = NULL;
	}
	FD_ZERO(&readfds);
        FD_SET(s, &readfds);
	if (select(s + 1, &readfds, NULL, NULL, NULL) < 1)
	    continue;
	cnt = recvfrom(s, buf, 4, MSG_PEEK | MSG_TRUNC, (struct sockaddr *)&from, &fromlen);
	if (cnt == -1) {
	    debug(DBG_WARN, "radudpget: recv failed");
	    continue;
	}
	if (cnt < 20) {
	    debug(DBG_WARN, "radudpget: length too small");
	    recv(s, buf, 4, 0);
	    continue;
	}
	
	p = client
	    ? find_clconf(RAD_UDP, (struct sockaddr *)&from, NULL)
	    : find_srvconf(RAD_UDP, (struct sockaddr *)&from, NULL);
	if (!p) {
	    debug(DBG_WARN, "radudpget: got packet from wrong or unknown UDP peer %s, ignoring", addr2string((struct sockaddr *)&from));
	    recv(s, buf, 4, 0);
	    continue;
	}
	
	len = RADLEN(buf);
	if (len < 20) {
	    debug(DBG_WARN, "radudpget: length too small");
	    recv(s, buf, 4, 0);
	    continue;
	}
	    
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "radudpget: malloc failed");
	    recv(s, buf, 4, 0);
	    continue;
	}
	
	cnt = recv(s, rad, len, MSG_TRUNC);
	debug(DBG_DBG, "radudpget: got %d bytes from %s", cnt, addr2string((struct sockaddr *)&from));

	if (cnt < len) {
	    debug(DBG_WARN, "radudpget: packet smaller than length field in radius header");
	    continue;
	}
	if (cnt > len)
	    debug(DBG_DBG, "radudpget: packet was padded with %d bytes", cnt - len);

	if (client) {
	    pthread_mutex_lock(p->lock);
	    for (node = list_first(p->clients); node; node = list_next(node)) {
		c = (struct client *)node->data;
		if (s == c->sock && addr_equal((struct sockaddr *)&from, c->addr))
		    break;
	    }
	    if (!node) {
		fromcopy = addr_copy((struct sockaddr *)&from);
		if (!fromcopy) {
		    pthread_mutex_unlock(p->lock);
		    continue;
		}
		c = addclient(p, 0);
		if (!c) {
		    free(fromcopy);
		    pthread_mutex_unlock(p->lock);
		    continue;
		}
		c->sock = s;
		c->addr = fromcopy;
	    }
	    *client = c;
	    pthread_mutex_unlock(p->lock);
	} else if (server)
	    *server = p->servers;
	break;
    }
    if (port)
	*port = port_get((struct sockaddr *)&from);
    return rad;
}

int clientradputudp(struct server *server, unsigned char *rad) {
    size_t len;
    struct sockaddr_storage sa;
    struct sockaddr *sap;
    struct clsrvconf *conf = server->conf;
    uint16_t port;
    
    len = RADLEN(rad);
    port = port_get(conf->addrinfo->ai_addr);
    
    if (*rad == RAD_Accounting_Request) {
	sap = (struct sockaddr *)&sa;
	memcpy(sap, conf->addrinfo->ai_addr, conf->addrinfo->ai_addrlen);
	port_set(sap, ++port);
    } else
	sap = conf->addrinfo->ai_addr;

    if (sendto(server->sock, rad, len, 0, sap, conf->addrinfo->ai_addrlen) >= 0) {
	debug(DBG_DBG, "clienradputudp: sent UDP of length %d to %s port %d", len, conf->host, port);
	return 1;
    }

    debug(DBG_WARN, "clientradputudp: send failed");
    return 0;
}

void *udpclientrd(void *arg) {
    struct server *server;
    unsigned char *buf;
    int *s = (int *)arg;
    
    for (;;) {
	server = NULL;
	buf = radudpget(*s, NULL, &server, NULL);
	replyh(server, buf);
    }
}

void *udpserverrd(void *arg) {
    struct request *rq;
    int *sp = (int *)arg;
    
    for (;;) {
	rq = newrequest();
	if (!rq) {
	    sleep(5); /* malloc failed */
	    continue;
	}
	rq->buf = radudpget(*sp, &rq->from, NULL, &rq->udpport);
	rq->udpsock = *sp;
	radsrv(rq);
    }
    free(sp);
}

void *udpserverwr(void *arg) {
    struct queue *replyq = (struct queue *)arg;
    struct request *reply;
    struct sockaddr_storage to;
    
    for (;;) {
	pthread_mutex_lock(&replyq->mutex);
	while (!(reply = (struct request *)list_shift(replyq->entries))) {
	    debug(DBG_DBG, "udp server writer, waiting for signal");
	    pthread_cond_wait(&replyq->cond, &replyq->mutex);
	    debug(DBG_DBG, "udp server writer, got signal");
	}
	pthread_mutex_unlock(&replyq->mutex);

	memcpy(&to, reply->from->addr, SOCKADDRP_SIZE(reply->from->addr));
	port_set((struct sockaddr *)&to, reply->udpport);
	if (sendto(reply->udpsock, reply->replybuf, RADLEN(reply->replybuf), 0, (struct sockaddr *)&to, SOCKADDR_SIZE(to)) < 0)
	    debug(DBG_WARN, "udpserverwr: send failed");
	debug(DBG_DBG, "udpserverwr: refcount %d", reply->refcount);
	freerq(reply);
    }
}

void addclientudp(struct client *client) {
    client->replyq = server_replyq;
}

void addserverextraudp(struct clsrvconf *conf) {
    switch (conf->addrinfo->ai_family) {
    case AF_INET:
	if (client4_sock < 0) {
	    client4_sock = bindtoaddr(getsrcprotores(RAD_UDP), AF_INET, 0, 1);
	    if (client4_sock < 0)
		debugx(1, DBG_ERR, "addserver: failed to create client socket for server %s", conf->host);
	}
	conf->servers->sock = client4_sock;
	break;
    case AF_INET6:
	if (client6_sock < 0) {
	    client6_sock = bindtoaddr(getsrcprotores(RAD_UDP), AF_INET6, 0, 1);
	    if (client6_sock < 0)
		debugx(1, DBG_ERR, "addserver: failed to create client socket for server %s", conf->host);
	}
	conf->servers->sock = client6_sock;
	break;
    default:
	debugx(1, DBG_ERR, "addserver: unsupported address family");
    }
}

void initextraudp() {
    pthread_t cl4th, cl6th, srvth;
    
    if (client4_sock >= 0)
	if (pthread_create(&cl4th, NULL, udpclientrd, (void *)&client4_sock))
	    debugx(1, DBG_ERR, "pthread_create failed");
    if (client6_sock >= 0)
	if (pthread_create(&cl6th, NULL, udpclientrd, (void *)&client6_sock))
	    debugx(1, DBG_ERR, "pthread_create failed");

    if (find_clconf_type(RAD_UDP, NULL)) {
	server_replyq = newqueue();
	if (pthread_create(&srvth, NULL, udpserverwr, (void *)server_replyq))
	    debugx(1, DBG_ERR, "pthread_create failed");
    }
}
