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
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <poll.h>
#include <ctype.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <regex.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include "radsecproxy.h"
#include "hostport.h"

#ifdef RADPROT_TLS
#include "debug.h"
#include "util.h"

static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs();
void *tlslistener(void *arg);
int tlsconnect(struct server *server, int timeout, char *text);
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

int tlsconnect(struct server *server, int timeout, char *text) {
    struct timeval now, start;
    time_t wait;
    int firsttry = 1;
    X509 *cert;
    SSL_CTX *ctx = NULL;
    unsigned long error;
    int origflags;
    struct addrinfo *source = NULL;

    debug(DBG_DBG, "tlsconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);
    if (server->state == RSP_SERVER_STATE_CONNECTED)
        server->state = RSP_SERVER_STATE_RECONNECTING;
    pthread_mutex_unlock(&server->lock);

    if(server->conf->source) {
        source = resolvepassiveaddrinfo(server->conf->source, AF_UNSPEC, NULL, protodefs.socktype);
        if(!source)
            debug(DBG_WARN, "tlsconnect: could not resolve source address to bind for server %s, using default", server->conf->name);
    }

    gettimeofday(&start, NULL);

    for (;;) {
        /* ensure previous connection is properly closed */
        if (server->ssl)
            SSL_shutdown(server->ssl);
        if (server->sock >= 0)
            close(server->sock);
        if (server->ssl)
            SSL_free(server->ssl);
        server->ssl = NULL;

        wait = connect_wait(start, server->connecttime, firsttry);
        debug(DBG_INFO, "Next connection attempt to %s in %lds", server->conf->name, wait);
        sleep(wait);
        firsttry = 0;

        gettimeofday(&now, NULL);
        if (timeout && (now.tv_sec - start.tv_sec) > timeout) {
            debug(DBG_DBG, "tlsconnect: timeout");
            if (source) freeaddrinfo(source);
            return 0;
        }

        debug(DBG_INFO, "tlsconnect: connecting to %s", server->conf->name);
        if ((server->sock = connecttcphostlist(server->conf->hostports, source ? source : srcres)) < 0)
            continue;
        if (server->conf->keepalive)
            enable_keepalive(server->sock);

        pthread_mutex_lock(&server->conf->tlsconf->lock);
        if (!(ctx = tlsgetctx(handle, server->conf->tlsconf))){
            pthread_mutex_unlock(&server->conf->tlsconf->lock);
            continue;
        }

        server->ssl = SSL_new(ctx);
        pthread_mutex_unlock(&server->conf->tlsconf->lock);
        if (!server->ssl)
            continue;

        SSL_set_fd(server->ssl, server->sock);
        if (sslconnecttimeout(server->ssl, 5) <= 0) {
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "tlsconnect: SSL connect to %s failed: %s", server->conf->name, ERR_error_string(error, NULL));
            debug(DBG_ERR, "tlsconnect: SSL connect to %s failed", server->conf->name, ERR_error_string(error, NULL));
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

    origflags = fcntl(server->sock, F_GETFL, 0);
    if (origflags == -1) {
        debugerrno(errno, DBG_WARN, "Failed to get flags");
    } else if (fcntl(server->sock, F_SETFL, origflags | O_NONBLOCK) == -1) {
        debugerrno(errno, DBG_WARN, "Failed to set O_NONBLOCK");
    }

    pthread_mutex_lock(&server->lock);
    server->state = RSP_SERVER_STATE_CONNECTED;
    gettimeofday(&server->connecttime, NULL);
    server->lostrqs = 0;
    pthread_mutex_unlock(&server->lock);
    pthread_mutex_lock(&server->newrq_mutex);
    server->conreset = 1;
    pthread_cond_signal(&server->newrq_cond);
    pthread_mutex_unlock(&server->newrq_mutex);
    if (source) freeaddrinfo(source);
    return 1;
}

/* timeout in seconds, 0 means no timeout (blocking), returns when num bytes have been read, or timeout */
/* returns 0 on timeout, -1 on error and num if ok */
int sslreadtimeout(SSL *ssl, unsigned char *buf, int num, int timeout, pthread_mutex_t *lock) {
    int ndesc, cnt = 0, len, sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    struct pollfd fds[1];
    unsigned long error;
    uint8_t want_write = 0;
    assert(lock);

    pthread_mutex_lock(lock);

    for (len = 0; len < num; len += cnt) {
        if (SSL_pending(ssl) == 0) {
            fds[0].fd = SSL_get_fd(ssl);
            fds[0].events = POLLIN;
            if (want_write) {
                fds[0].events |= POLLOUT;
                want_write = 0;
            }
            pthread_mutex_unlock(lock);

            ndesc = poll(fds, 1, timeout ? timeout * 1000 : -1);
            if (ndesc == 0)
                return ndesc;

            pthread_mutex_lock(lock);
            if (ndesc < 0 || fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                if (fds[0].revents & POLLERR) {
                    if(!getsockopt(SSL_get_fd(ssl), SOL_SOCKET, SO_ERROR, (void *)&sockerr, &errlen))
                        debug(DBG_INFO, "TLS Connection lost: %s", strerror(sockerr));
                    else
                        debug(DBG_INFO, "TLS Connection lost: unknown error");
                } else if (fds[0].revents & POLLHUP) {
                    debug(DBG_INFO, "TLS Connection lost: hang up");
                } else if (fds[0].revents & POLLNVAL) {
                    debug(DBG_INFO, "TLS Connection error: fd not open");
                }

                SSL_shutdown(ssl);
                pthread_mutex_unlock(lock);
                return -1;
            }
        }

        cnt = SSL_read(ssl, buf + len, num - len);
        if (cnt <= 0) {
            switch (SSL_get_error(ssl, cnt)) {
                case SSL_ERROR_WANT_WRITE:
                    want_write = 1;
                case SSL_ERROR_WANT_READ:
                    cnt = 0;
                    continue;
                case SSL_ERROR_ZERO_RETURN:
                    debug(DBG_DBG, "sslreadtimeout: got ssl shutdown");
                default:
                    while ((error = ERR_get_error()))
                        debug(DBG_ERR, "sslreadtimeout: SSL: %s", ERR_error_string(error, NULL));
                    if (cnt == 0)
                        debug(DBG_INFO, "sslreadtimeout: connection closed by remote host");
                    else {
                        debugerrno(errno, DBG_ERR, "sslreadtimeout: connection lost");
                    }
                    /* ensure ssl connection is shutdown */
                    SSL_shutdown(ssl);
                    pthread_mutex_unlock(lock);
                    return -1;
            }
        }
    }
    pthread_mutex_unlock(lock);
    return cnt;
}

/* timeout in seconds, 0 means no timeout (blocking) */
unsigned char *radtlsget(SSL *ssl, int timeout, pthread_mutex_t *lock) {
    int cnt, len;
    unsigned char buf[4], *rad;

	cnt = sslreadtimeout(ssl, buf, 4, timeout, lock);
	if (cnt < 1)
        return NULL;

	len = RADLEN(buf);
	if (len < 20) {
	    debug(DBG_ERR, "radtlsget: length too small, malformed packet! closing connection!");
        pthread_mutex_lock(lock);
        SSL_shutdown(ssl);
        pthread_mutex_unlock(lock);
        return NULL;
	}
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "radtlsget: malloc failed");
	    return NULL;
	}
	memcpy(rad, buf, 4);

	cnt = sslreadtimeout(ssl, rad + 4, len - 4, timeout, lock);
	if (cnt < 1) {
	    free(rad);
	    return NULL;
	}

    debug(DBG_DBG, "radtlsget: got %d bytes", len);
    return rad;
}

int dosslwrite(SSL *ssl, void *buf, int num, uint8_t may_block){
    int ret;
    unsigned long error;
    struct pollfd fds[1];

    if (!buf || !num) {
            debug(DBG_ERR, "dosslwrite: was called with empty buffer!");
            return -1;
    }

    if(!may_block) {
        fds[0].fd = SSL_get_fd(ssl);
        fds[0].events = POLLOUT;
        if (poll(fds, 1, 0) <= 0 || fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            debug(DBG_DBG, "dosslwrite: socket not ready or buffer full; avoid blocking...");
            return -1;
        }
    }

    while ((ret = SSL_write(ssl, buf, num)) <= 0) {
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                while ((error = ERR_get_error()))
                    debug(DBG_ERR, "dosslwrite: SSL: %s", ERR_error_string(error, NULL));
                return ret;
        }
    }
    return ret;
}

int clientradputtls(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    struct clsrvconf *conf = server->conf;

    pthread_mutex_lock(&server->lock);
    if (server->state != RSP_SERVER_STATE_CONNECTED) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }

    len = RADLEN(rad);
    if ((cnt = dosslwrite(server->ssl, rad, len, 0)) <= 0) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }

    debug(DBG_DBG, "clientradputtls: Sent %d bytes, Radius packet of length %d to TLS peer %s", cnt, len, conf->name);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

void *tlsclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    struct timeval now;

    for (;;) {
	buf = radtlsget(server->ssl, server->conf->retryinterval * (server->conf->retrycount+1), &server->lock);
	if (!buf) {
        if (SSL_get_shutdown(server->ssl) || (server->lostrqs && server->conf->statusserver!=RSP_STATSRV_OFF)) {
            if (SSL_get_shutdown(server->ssl))
                debug (DBG_WARN, "tlsclientrd: connection to server %s lost", server->conf->name);
            else if (server->lostrqs)
                debug (DBG_WARN, "tlsclientrd: server %s did not respond, closing connection.", server->conf->name);
            if (server->dynamiclookuparg)
                break;
            tlsconnect(server, 0, "tlsclientrd");
        }
        if (server->dynamiclookuparg) {
            gettimeofday(&now, NULL);
            if (now.tv_sec - server->lastreply.tv_sec > IDLE_TIMEOUT) {
                debug(DBG_INFO, "tlsclientrd: idle timeout for %s", server->conf->name);
                break;
            }
        }
        continue;
    }

	replyh(server, buf);

    }
    debug(DBG_INFO, "tlsclientrd: exiting for %s", server->conf->name);
    pthread_mutex_lock(&server->lock);
    server->state = RSP_SERVER_STATE_FAILING;
    SSL_shutdown(server->ssl);
    shutdown(server->sock, SHUT_RDWR);
    close(server->sock);

    /* Wake up clientwr(). */
    server->clientrdgone = 1;
    pthread_mutex_unlock(&server->lock);
    pthread_mutex_lock(&server->newrq_mutex);
    pthread_cond_signal(&server->newrq_cond);
    pthread_mutex_unlock(&server->newrq_mutex);
    return NULL;
}

void *tlsserverwr(void *arg) {
    int cnt;
    struct client *client = (struct client *)arg;
    struct gqueue *replyq;
    struct request *reply;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "tlsserverwr: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));
    replyq = client->replyq;
    for (;;) {
        pthread_mutex_lock(&replyq->mutex);
        while (!list_first(replyq->entries)) {
            if (client->ssl) {
                debug(DBG_DBG, "tlsserverwr: waiting for signal");
                pthread_cond_wait(&replyq->cond, &replyq->mutex);
                debug(DBG_DBG, "tlsserverwr: got signal");
            } else
                break;
        }

        reply = (struct request *)list_shift(replyq->entries);
        pthread_mutex_unlock(&replyq->mutex);

        pthread_mutex_lock(&client->lock);
        if (!client->ssl) {
            /* ssl might have changed while waiting */
            if (reply)
                freerq(reply);
            pthread_mutex_unlock(&client->lock);
            debug(DBG_DBG, "tlsserverwr: exiting as requested");
            pthread_exit(NULL);
        }

        if ((cnt = dosslwrite(client->ssl, reply->replybuf, RADLEN(reply->replybuf), 0)) > 0) {
            debug(DBG_DBG, "tlsserverwr: sent %d bytes, Radius packet of length %d to %s",
                cnt, RADLEN(reply->replybuf), addr2string(client->addr, tmp, sizeof(tmp)));
        }
        pthread_mutex_unlock(&client->lock);
    	freerq(reply);
    }
}

void tlsserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf;
    pthread_t tlsserverwrth;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "tlsserverrd: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));

    if (pthread_create(&tlsserverwrth, &pthread_attr, tlsserverwr, (void *)client)) {
	debug(DBG_ERR, "tlsserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	buf = radtlsget(client->ssl, IDLE_TIMEOUT * 3, &client->lock);
	if (!buf) {
	    debug(DBG_ERR, "tlsserverrd: connection from %s lost", addr2string(client->addr, tmp, sizeof(tmp)));
	    break;
	}
	debug(DBG_DBG, "tlsserverrd: got Radius message from %s", addr2string(client->addr, tmp, sizeof(tmp)));
	rq = newrequest();
	if (!rq) {
	    free(buf);
	    continue;
	}
	rq->buf = buf;
	rq->from = client;
	if (!radsrv(rq)) {
	    debug(DBG_ERR, "tlsserverrd: message authentication/validation failed, closing connection from %s", addr2string(client->addr, tmp, sizeof(tmp)));
	    break;
	}
    }

    /* stop writer by setting ssl to NULL and give signal in case waiting for data */
    pthread_mutex_lock(&client->lock);
    client->ssl = NULL;
    pthread_mutex_unlock(&client->lock);
    pthread_mutex_lock(&client->replyq->mutex);
    pthread_cond_signal(&client->replyq->cond);
    pthread_mutex_unlock(&client->replyq->mutex);
    debug(DBG_DBG, "tlsserverrd: waiting for writer to end");
    pthread_join(tlsserverwrth, NULL);
    debug(DBG_DBG, "tlsserverrd: reader for %s exiting", addr2string(client->addr, tmp, sizeof(tmp)));
}

void *tlsservernew(void *arg) {
    int s, origflags;
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
    char tmp[INET6_ADDRSTRLEN];

    s = *(int *)arg;
    free(arg);
    if (getpeername(s, (struct sockaddr *)&from, &fromlen)) {
	debug(DBG_DBG, "tlsservernew: getpeername failed, exiting");
	goto exit;
    }
    debug(DBG_WARN, "tlsservernew: incoming TLS connection from %s", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));

    conf = find_clconf(handle, (struct sockaddr *)&from, &cur);
    if (conf) {
        pthread_mutex_lock(&conf->tlsconf->lock);
        ctx = tlsgetctx(handle, conf->tlsconf);
        if (!ctx) {
            pthread_mutex_unlock(&conf->tlsconf->lock);
            goto exit;
        }

        ssl = SSL_new(ctx);
        pthread_mutex_unlock(&conf->tlsconf->lock);
        if (!ssl)
            goto exit;

        SSL_set_fd(ssl, s);
        if (sslaccepttimeout(ssl, 30) <= 0) {
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "tlsservernew: SSL accept from %s failed: %s", conf->name, ERR_error_string(error, NULL));
            debug(DBG_ERR, "tlsservernew: SSL_accept failed");
            goto exit;
        }
        cert = verifytlscert(ssl);
        if (!cert)
            goto exit;
        accepted_tls = conf->tlsconf;
    }

    origflags = fcntl(s, F_GETFL, 0);
    if (origflags == -1) {
        debugerrno(errno, DBG_WARN, "Failed to get flags");
    } else if (fcntl(s, F_SETFL, origflags | O_NONBLOCK) == -1) {
        debugerrno(errno, DBG_WARN, "Failed to set O_NONBLOCK");
    }

    while (conf) {
        if (accepted_tls == conf->tlsconf && verifyconfcert(cert, conf)) {
            X509_free(cert);
            client = addclient(conf, 1);
            if (client) {
                if (conf->keepalive)
                    enable_keepalive(s);
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
    shutdown(s, SHUT_RDWR);
    close(s);
    pthread_exit(NULL);
}

void *tlslistener(void *arg) {
    pthread_t tlsserverth;
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
	if (pthread_create(&tlsserverth, &pthread_attr, tlsservernew, (void *) s_arg)) {
	    debug(DBG_ERR, "tlslistener: pthread_create failed");
            free(s_arg);
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
