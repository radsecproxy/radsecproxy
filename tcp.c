/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2012, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef SYS_SOLARIS
#include <fcntl.h>
#endif
#include "hostport.h"
#include "list.h"
#include "radsecproxy.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef RADPROT_TCP
#include "debug.h"
#include "util.h"
static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs(void);
void *tcplistener(void *arg);
int tcpconnect(struct server *server, int timeout, int reconnect);
void *tcpclientrd(void *arg);
int clientradputtcp(struct server *server, unsigned char *rad, int radlen);
void tcpsetsrcres(void);

static const struct protodefs protodefs = {
    "tcp",
    NULL,                                        /* secretdefault */
    SOCK_STREAM,                                 /* socktype */
    "1812",                                      /* portdefault */
    0,                                           /* retrycountdefault */
    0,                                           /* retrycountmax */
    REQUEST_RETRY_INTERVAL *REQUEST_RETRY_COUNT, /* retryintervaldefault */
    60,                                          /* retryintervalmax */
    DUPLICATE_INTERVAL,                          /* duplicateintervaldefault */
    setprotoopts,                                /* setprotoopts */
    getlistenerargs,                             /* getlistenerargs */
    tcplistener,                                 /* listener */
    tcpconnect,                                  /* connecter */
    tcpclientrd,                                 /* clientconnreader */
    clientradputtcp,                             /* clientradput */
    NULL,                                        /* addclient */
    NULL,                                        /* addserverextra */
    tcpsetsrcres,                                /* setsrcres */
    NULL                                         /* initextra */
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

static char **getlistenerargs(void) {
    return protoopts ? protoopts->listenargs : NULL;
}

void tcpsetsrcres(void) {
    if (!srcres)
        srcres =
            resolvepassiveaddrinfo(protoopts ? protoopts->sourcearg : NULL,
                                   AF_UNSPEC, NULL, protodefs.socktype);
}

int tcpconnect(struct server *server, int timeout, int reconnect) {
    struct timeval now, start;
    int firsttry = 1;
    uint32_t wait;
    struct addrinfo *source = NULL;
    struct list_node *entry;
    struct hostportres *hp;

    debug(DBG_DBG, "tcpconnect: %s to %s", reconnect ? "reconnecting" : "initial connection", server->conf->name);
    pthread_mutex_lock(&server->lock);
    if (server->state == RSP_SERVER_STATE_CONNECTED)
        server->state = RSP_SERVER_STATE_RECONNECTING;
    pthread_mutex_unlock(&server->lock);

    if (server->conf->source) {
        source = resolvepassiveaddrinfo(server->conf->source, AF_UNSPEC, NULL, protodefs.socktype);
        if (!source)
            debug(DBG_WARN, "tcpconnect: could not resolve source address to bind for server %s, using default", server->conf->name);
    }

    gettimeofday(&start, NULL);

    for (;;) {
        if (server->sock >= 0)
            close(server->sock);
        server->sock = -1;

        wait = connect_wait(start, server->connecttime, firsttry);
        gettimeofday(&now, NULL);
        if (timeout && (now.tv_sec - start.tv_sec) + wait > timeout) {
            debug(DBG_DBG, "tcpconnect: timeout");
            if (source)
                freeaddrinfo(source);
            return 0;
        }
        if (wait)
            debug(DBG_INFO, "Next connection attempt to %s in %lds", server->conf->name, wait);
        sleep(wait);
        firsttry = 0;

        for (entry = list_first(server->conf->hostports); entry; entry = list_next(entry)) {
            hp = (struct hostportres *)entry->data;
            debug(DBG_INFO, "tcpconnect: trying to open TCP connection to server %s (%s port %s)", server->conf->name, hp->host, hp->port);
            if ((server->sock = connecttcp(hp->addrinfo, source ? source : srcres, list_count(server->conf->hostports) > 1 ? 5 : 30)) >= 0) {
                debug(DBG_WARN, "tcpconnect: TCP connection to server %s (%s port %s) up", server->conf->name, hp->host, hp->port);
                break;
            }
        }
        if (server->sock < 0) {
            debug(DBG_ERR, "tcpconnect: TCP connection to server %s failed", server->conf->name);
            continue;
        }

        if (server->conf->keepalive)
            enable_keepalive(server->sock);
        break;
    }
    pthread_mutex_lock(&server->lock);
    server->state = RSP_SERVER_STATE_CONNECTED;
    gettimeofday(&server->connecttime, NULL);
    server->lostrqs = 0;
    pthread_mutex_unlock(&server->lock);
    pthread_mutex_lock(&server->newrq_mutex);
    server->conreset = reconnect;
    pthread_cond_signal(&server->newrq_cond);
    pthread_mutex_unlock(&server->newrq_mutex);

    if (source)
        freeaddrinfo(source);
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
        ndesc = poll(fds, 1, timeout ? timeout * 1000 : -1);
        if (ndesc < 1)
            return ndesc;

        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            return -1;
        }
        cnt = read(s, buf + len, num - len);
        if (cnt <= 0)
            return -1;
    }
    return num;
}

/* timeout in seconds, 0 means no timeout (blocking)
   return 0 on timeout, <0 on error */
int radtcpget(int s, int timeout, uint8_t **buf) {
    int cnt, len;
    unsigned char init_buf[4];

    cnt = tcpreadtimeout(s, init_buf, 4, timeout);
    if (cnt < 1) {
        debug(DBG_DBG, cnt ? "radtcpget: connection lost" : "radtcpget: timeout");
        return cnt;
    }

    len = get_checked_rad_length(init_buf);
    if (len <= 0) {
        debug(DBG_ERR, "radtcpget: invalid message length (%d)! closing connection!", -len);
        return len;
    }

    *buf = malloc(len);
    if (!*buf) {
        debug(DBG_ERR, "radtcpget: malloc failed! closing connection!");
        return -1;
    }
    memcpy(*buf, init_buf, 4);

    cnt = tcpreadtimeout(s, *buf + 4, len - 4, timeout);
    if (cnt < 1) {
        debug(DBG_DBG, cnt ? "radtcpget: connection lost" : "radtcpget: timeout");
        free(*buf);
        *buf = NULL;
        return cnt;
    }
    debug(DBG_DBG, "radtcpget: got %d bytes", len);
    return len;
}

int clientradputtcp(struct server *server, unsigned char *rad, int radlen) {
    int cnt;
    struct clsrvconf *conf = server->conf;

    if (radlen <= 0) {
        debug(DBG_ERR, "clientradputtcp: invalid buffer (length)");
        return 0;
    }
    pthread_mutex_lock(&server->lock);
    if (server->state != RSP_SERVER_STATE_CONNECTED) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }
    if ((cnt = write(server->sock, rad, radlen)) <= 0) {
        debug(DBG_ERR, "clientradputtcp: write error");
        pthread_mutex_unlock(&server->lock);
        return 0;
    }
    debug(DBG_DBG, "clientradputtcp: Sent %d bytes, Radius packet of length %zu to TCP peer %s", cnt, radlen, conf->name);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

void *tcpclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    int len = 0;

    for (;;) {
        len = radtcpget(server->sock, server->conf->retryinterval * (server->conf->retrycount + 1), &buf);
        if (buf && len > 0) {
            replyh(server, buf, len);
            buf = NULL;
        } else if (len == 0) {
            if (timeouth(server))
                break;
        } else {
            if (closeh(server))
                break;
        }
    }
    shutdown(server->sock, SHUT_RDWR);
    close(server->sock);

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
        cnt = write(client->sock, reply->replybuf, reply->replybuflen);
        if (cnt > 0)
            debug(DBG_DBG, "tcpserverwr: sent %d bytes, Radius packet of length %d to %s",
                  cnt, reply->replybuflen, addr2string(client->addr, tmp, sizeof(tmp)));
        else
            debug(DBG_ERR, "tcpserverwr: write error for %s", addr2string(client->addr, tmp, sizeof(tmp)));
        freerq(reply);
    }
}

void tcpserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf = NULL;
    pthread_t tcpserverwrth;
    char tmp[INET6_ADDRSTRLEN];
    int len = 0;

    debug(DBG_DBG, "tcpserverrd: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));

    if (pthread_create(&tcpserverwrth, &pthread_attr, tcpserverwr, (void *)client)) {
        debug(DBG_ERR, "tcpserverrd: pthread_create failed");
        return;
    }

    for (;;) {
        len = radtcpget(client->sock, 0, &buf);
        if (!buf || !len) {
            debug(DBG_ERR, "tcpserverrd: connection from %s lost", addr2string(client->addr, tmp, sizeof(tmp)));
            break;
        }
        debug(DBG_DBG, "tcpserverrd: got Radius message from %s", addr2string(client->addr, tmp, sizeof(tmp)));
        rq = newrequest();
        if (!rq) {
            free(buf);
            buf = NULL;
            continue;
        }
        rq->buf = buf;
        rq->buflen = len;
        rq->from = client;
        if (!radsrv(rq)) {
            debug(DBG_ERR, "tcpserverrd: message authentication/validation failed, closing connection from %s", addr2string(client->addr, tmp, sizeof(tmp)));
            break;
        }
        buf = NULL;
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

    conf = find_clconf(handle, (struct sockaddr *)&from, NULL, NULL);
    if (conf) {
        client = addclient(conf, 1);
        if (client) {
            if (conf->keepalive)
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

void tcpaccept(int s) {
    int *s_arg;
    pthread_t tcpserverth;

    s_arg = malloc(sizeof(s));
    if (!s_arg) {
        debug(DBG_ERR, "tcpaccept: malloc failed");
        return;
    }
    *s_arg = s;
    if (pthread_create(&tcpserverth, &pthread_attr, tcpservernew, (void *)s_arg)) {
        debug(DBG_ERR, "tcpaccept: pthread_create failed");
        free(s_arg);
        shutdown(s, SHUT_RDWR);
        close(s);
        return;
    }
    pthread_detach(tcpserverth);
}

void *tcplistener(void *arg) {
    accepttcp(*(int *)arg, tcpaccept);
    free(arg);
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
