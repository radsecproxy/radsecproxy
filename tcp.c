/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2012, NORDUnet A/S */
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
#include <poll.h>
#include <ctype.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <regex.h>
#include <pthread.h>
#include "radsecproxy.h"
#include "hostport.h"

#ifdef RADPROT_TCP
#include "debug.h"
#include "util.h"
static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs();
void *tcplistener(void *arg);
int tcpconnect(struct server *server, struct timeval *when, int timeout, char * text);
void *tcpclientrd(void *arg);
int clientradputtcp(struct server *server, unsigned char *rad);
void tcpsetsrcres();

static const struct protodefs protodefs = {
    "tcp",
    NULL, /* secretdefault */
    SOCK_STREAM, /* socktype */
    "1812", /* portdefault */
    0, /* retrycountdefault */
    0, /* retrycountmax */
    REQUEST_RETRY_INTERVAL * REQUEST_RETRY_COUNT, /* retryintervaldefault */
    60, /* retryintervalmax */
    DUPLICATE_INTERVAL, /* duplicateintervaldefault */
    setprotoopts, /* setprotoopts */
    getlistenerargs, /* getlistenerargs */
    tcplistener, /* listener */
    tcpconnect, /* connecter */
    tcpclientrd, /* clientconnreader */
    clientradputtcp, /* clientradput */
    NULL, /* addclient */
    NULL, /* addserverextra */
    tcpsetsrcres, /* setsrcres */
    NULL /* initextra */
};

static struct addrinfo *srcres = NULL;
static uint8_t handle;
static struct commonprotoopts *protoopts = NULL;
const struct protodefs *tcpinit(uint8_t h) {
    handle = h;
    return &protodefs;
}

static void setprotoopts(struct commonprotoopts *opts) {
    protoopts = opts;
}

static char **getlistenerargs() {
    return protoopts ? protoopts->listenargs : NULL;
}

void tcpsetsrcres() {
    if (!srcres)
	srcres =
            resolvepassiveaddrinfo(protoopts ? protoopts->sourcearg : NULL,
                                   AF_UNSPEC, NULL, protodefs.socktype);
}

int tcpconnect(struct server *server, struct timeval *when, int timeout, char *text) {
    struct timeval now, start = {0,0};
    time_t elapsed;
    uint8_t initialdelay = 0;

    debug(DBG_DBG, "tcpconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);

    if (server->state == RSP_SERVER_STATE_CONNECTED)
        server->state = RSP_SERVER_STATE_RECONNECTING;

    gettimeofday(&now, NULL);
    if (when && (now.tv_sec - when->tv_sec) < 30 ) {
        elapsed = 30 - (now.tv_sec - when->tv_sec);
        initialdelay = 1;
        start.tv_sec = now.tv_sec + elapsed;
    }

    for (;;) {
        if (server->sock >= 0)
            close(server->sock);
        server->sock = -1;

        /* no sleep at startup or at first try */
        if (start.tv_sec) {
            gettimeofday(&now, NULL);
            if (!initialdelay)
                elapsed = now.tv_sec - start.tv_sec;

            if (timeout && elapsed > timeout) {
                debug(DBG_DBG, "tlsconnect: timeout");
                pthread_mutex_unlock(&server->lock);
                return 0;
            }

            /* give up lock while sleeping for next try */
            pthread_mutex_unlock(&server->lock);
            if (elapsed < 1)
                sleep(2);
            else {
                debug(DBG_INFO, "Next connection attempt in %lds", elapsed < 60 ? elapsed : 60);
                sleep(elapsed < 60 ? elapsed : 60);
            }
            if (initialdelay)
                initialdelay = 0;
            pthread_mutex_lock(&server->lock);
            debug(DBG_INFO, "tlsconnect: retry connecting");
        } else {
            gettimeofday(&start, NULL);
        }

        if ((server->sock = connecttcphostlist(server->conf->hostports, srcres)) < 0)
            continue;
        if (server->conf->keepalive)
            enable_keepalive(server->sock);
        break;
    }
    server->state = RSP_SERVER_STATE_CONNECTED;
    gettimeofday(&server->lastconnecttry, NULL);
    server->lostrqs = 0;
    pthread_mutex_unlock(&server->lock);
    return 1;
}

/* timeout in seconds, 0 means no timeout (blocking), returns when num bytes have been read, or timeout */
/* returns 0 on timeout, -1 on error and num if ok */
int tcpreadtimeout(int s, unsigned char *buf, int num, int timeout) {
    int ndesc, cnt, len;
    struct pollfd fds[1];

    if (s < 0)
	return -1;
    /* make socket non-blocking? */
    for (len = 0; len < num; len += cnt) {
        fds[0].fd = s;
        fds[0].events = POLLIN;
	ndesc = poll(fds, 1, timeout? timeout * 1000 : -1);
	if (ndesc < 1)
	    return ndesc;

    if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL) ) {
        return -1;
    }
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
	if (len < 4) {
	    debug(DBG_ERR, "radtcpget: length too small");
	    continue;
	}
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
    struct clsrvconf *conf = server->conf;

    if (server->state != RSP_SERVER_STATE_CONNECTED)
	return 0;
    len = RADLEN(rad);
    if ((cnt = write(server->sock, rad, len)) <= 0) {
	debug(DBG_ERR, "clientradputtcp: write error");
	return 0;
    }
    debug(DBG_DBG, "clientradputtcp: Sent %d bytes, Radius packet of length %d to TCP peer %s", cnt, len, conf->name);
    return 1;
}

void *tcpclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    struct timeval lastconnecttry;

    for (;;) {
	/* yes, lastconnecttry is really necessary */
	lastconnecttry = server->lastconnecttry;
	buf = radtcpget(server->sock, server->dynamiclookuparg ? IDLE_TIMEOUT : 0);
	if (!buf) {
        if (server->dynamiclookuparg)
		break;
	    tcpconnect(server, &lastconnecttry, 0, "tcpclientrd");
	    continue;
	}

	replyh(server, buf);
    }
    server->clientrdgone = 1;
    pthread_mutex_lock(&server->newrq_mutex);
    pthread_cond_signal(&server->newrq_cond);
    pthread_mutex_unlock(&server->newrq_mutex);
    return NULL;
}

void *tcpserverwr(void *arg) {
    int cnt;
    struct client *client = (struct client *)arg;
    struct gqueue *replyq;
    struct request *reply;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "tcpserverwr: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));
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
	reply = (struct request *)list_shift(replyq->entries);
	pthread_mutex_unlock(&replyq->mutex);
	cnt = write(client->sock, reply->replybuf, RADLEN(reply->replybuf));
	if (cnt > 0)
	    debug(DBG_DBG, "tcpserverwr: sent %d bytes, Radius packet of length %d to %s",
		  cnt, RADLEN(reply->replybuf), addr2string(client->addr, tmp, sizeof(tmp)));
	else
	    debug(DBG_ERR, "tcpserverwr: write error for %s", addr2string(client->addr, tmp, sizeof(tmp)));
	freerq(reply);
    }
}

void tcpserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf;
    pthread_t tcpserverwrth;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "tcpserverrd: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));

    if (pthread_create(&tcpserverwrth, &pthread_attr, tcpserverwr, (void *)client)) {
	debug(DBG_ERR, "tcpserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	buf = radtcpget(client->sock, 0);
	if (!buf) {
	    debug(DBG_ERR, "tcpserverrd: connection from %s lost", addr2string(client->addr, tmp, sizeof(tmp)));
	    break;
	}
	debug(DBG_DBG, "tcpserverrd: got Radius message from %s", addr2string(client->addr, tmp, sizeof(tmp)));
	rq = newrequest();
	if (!rq) {
	    free(buf);
	    continue;
	}
	rq->buf = buf;
	rq->from = client;
	if (!radsrv(rq)) {
	    debug(DBG_ERR, "tcpserverrd: message authentication/validation failed, closing connection from %s", addr2string(client->addr, tmp, sizeof(tmp)));
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
    debug(DBG_DBG, "tcpserverrd: reader for %s exiting", addr2string(client->addr, tmp, sizeof(tmp)));
}
void *tcpservernew(void *arg) {
    int s;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    struct clsrvconf *conf;
    struct client *client;
    char tmp[INET6_ADDRSTRLEN];

    s = *(int *)arg;
    free(arg);
    if (getpeername(s, (struct sockaddr *)&from, &fromlen)) {
	debug(DBG_DBG, "tcpservernew: getpeername failed, exiting");
	goto exit;
    }
    debug(DBG_WARN, "tcpservernew: incoming TCP connection from %s", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));

    conf = find_clconf(handle, (struct sockaddr *)&from, NULL);
    if (conf) {
        client = addclient(conf, 1);
        if (client) {
            if(conf->keepalive)
                enable_keepalive(s);
            client->sock = s;
            client->addr = addr_copy((struct sockaddr *)&from);
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
    int s, *sp = (int *)arg, *s_arg = NULL;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);

    listen(*sp, 128);

    for (;;) {
	s = accept(*sp, (struct sockaddr *)&from, &fromlen);
	if (s < 0) {
	    debug(DBG_WARN, "accept failed");
	    continue;
	}
        s_arg = malloc(sizeof(s));
        if (!s_arg)
            debugx(1, DBG_ERR, "malloc failed");
        *s_arg = s;
	if (pthread_create(&tcpserverth, &pthread_attr, tcpservernew, (void *) s_arg)) {
	    debug(DBG_ERR, "tcplistener: pthread_create failed");
            free(s_arg);
	    shutdown(s, SHUT_RDWR);
	    close(s);
	    continue;
	}
	pthread_detach(tcpserverth);
    }
    free(sp);
    return NULL;
}
#else
const struct protodefs *tcpinit(uint8_t h) {
    return NULL;
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
