/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2012,2016-2017, NORDUnet A/S */
/* See LICENSE for licensing information. */

#define _GNU_SOURCE

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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include "hash.h"
#include "radsecproxy.h"

#ifdef RADPROT_DTLS
#include "debug.h"
#include "util.h"
#include "hostport.h"

static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs();
void *dtlslistener(void *arg);
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
    dtlslistener, /* listener */
    dtlsconnect, /* connecter */
    dtlsclientrd, /* clientconnreader */
    clientradputdtls, /* clientradput */
    NULL, /* addclient */
    NULL, /* addserverextra */
    dtlssetsrcres, /* setsrcres */
    NULL /* initextra */
};

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

struct dtlsservernewparams {
    struct sockaddr_storage addr;
    struct sockaddr_storage bind;
    SSL *ssl;
};

void dtlssetsrcres() {
    if (!srcres)
	srcres =
            resolvepassiveaddrinfo(protoopts ? protoopts->sourcearg : NULL,
                                   AF_UNSPEC, NULL, protodefs.socktype);
}

int dtlsread(SSL *ssl, unsigned char *buf, int num, int timeout, pthread_mutex_t *lock) {
    int len, cnt;
    struct pollfd fds[1];
    unsigned long error;
    assert(lock);

    pthread_mutex_lock(lock);

    for (len = 0; len < num; len += cnt) {
        if (!SSL_pending(ssl)) {
            fds[0].fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
            fds[0].events = POLLIN;

            pthread_mutex_unlock(lock);

            cnt = poll(fds, 1, timeout? timeout * 1000 : -1);
            if (cnt < 1)
                return cnt;
            if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                pthread_mutex_lock(lock);
                SSL_shutdown(ssl);
                pthread_mutex_unlock(lock);
                return -1;
            }

            pthread_mutex_lock(lock);
        }

        cnt = SSL_read(ssl, buf + len, num - len);
        if (cnt <= 0)
            switch (cnt = SSL_get_error(ssl, cnt)) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    cnt = 0;
                    continue;
                case SSL_ERROR_ZERO_RETURN:
                    debug(DBG_DBG, "dtlsread: got ssl shutdown");
                default:
                    while ((error = ERR_get_error()))
                        debug(DBG_ERR, "dtlsread: SSL: %s", ERR_error_string(error, NULL));
                    /* snsure ssl connection is shutdown */
                    SSL_shutdown(ssl);
                    pthread_mutex_unlock(lock);
                    return -1;
        }
    }
    pthread_mutex_unlock(lock);
    return num;
}

unsigned char *raddtlsget(SSL *ssl, int timeout, pthread_mutex_t *lock) {
    int cnt, len;
    unsigned char buf[4], *rad;

    cnt = dtlsread(ssl, buf, 4, timeout, lock);
    if (cnt < 1) {
        debug(DBG_DBG, cnt ? "raddtlsget: connection lost" : "raddtlsget: timeout");
        return NULL;
    }

    len = RADLEN(buf);
    if (len < 20) {
        debug(DBG_ERR, "raddtlsget: length too small, malformed packet! closing conneciton!");
        return NULL;
    }
    rad = malloc(len);
    if (!rad) {
        debug(DBG_ERR, "raddtlsget: malloc failed");
        return NULL;
    }
    memcpy(rad, buf, 4);

    cnt = dtlsread(ssl, rad + 4, len - 4, timeout, lock);
    if (cnt < 1) {
        debug(DBG_DBG, cnt ? "raddtlsget: connection lost" : "raddtlsget: timeout");
        free(rad);
        return NULL;
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
            } else
                break;
        }

        reply = (struct request *)list_shift(replyq->entries);
        pthread_mutex_unlock(&replyq->mutex);

        pthread_mutex_lock(&client->lock);
        if (!client->ssl) {
            /* ssl might have changed while waiting */
            pthread_mutex_unlock(&client->lock);
            if (reply)
                freerq(reply);
            debug(DBG_DBG, "tlsserverwr: exiting as requested");
            pthread_exit(NULL);
        }

        while ((cnt = SSL_write(client->ssl, reply->replybuf, RADLEN(reply->replybuf))) <= 0) {
            switch (SSL_get_error(client->ssl, cnt)) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    continue;
                default:
                    while ((error = ERR_get_error()))
                        debug(DBG_ERR, "dtlsserverwr: SSL: %s", ERR_error_string(error, NULL));
                    pthread_mutex_unlock(&client->lock);
                    freerq(reply);
                    debug(DBG_DBG, "tlsserverwr: SSL error. exiting.");
                    pthread_exit(NULL);
            }
        }
        debug(DBG_DBG, "dtlsserverwr: sent %d bytes, Radius packet of length %d to %s",
            cnt, RADLEN(reply->replybuf), addr2string(client->addr));
        pthread_mutex_unlock(&client->lock);
        freerq(reply);
    }
}

void dtlsserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf;
    pthread_t dtlsserverwrth;

    debug(DBG_DBG, "dtlsserverrd: starting for %s", addr2string(client->addr));

    if (pthread_create(&dtlsserverwrth, &pthread_attr, dtlsserverwr, (void *)client)) {
	debug(DBG_ERR, "dtlsserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	buf = raddtlsget(client->ssl, IDLE_TIMEOUT * 3, &client->lock);
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
    pthread_mutex_lock(&client->lock);
    client->ssl = NULL;
    pthread_mutex_unlock(&client->lock);
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
    X509 *cert = NULL;
    struct tls *accepted_tls = NULL;
    int s;
    unsigned long error;
    struct timeval timeout;
    struct addrinfo tmpsrvaddr;

    debug(DBG_WARN, "dtlsservernew: incoming DTLS connection from %s", addr2string((struct sockaddr *)&params->addr));

    if (!srcres)
        dtlssetsrcres();
    memcpy(&tmpsrvaddr, srcres, sizeof(struct addrinfo));
    tmpsrvaddr.ai_addr = (struct sockaddr *)&params->bind;
    tmpsrvaddr.ai_addrlen = SOCKADDR_SIZE(params->bind);
    if ((s = bindtoaddr(&tmpsrvaddr, params->addr.ss_family, 1)) < 0)
        goto exit;
    if (connect(s, (struct sockaddr *)&params->addr, SOCKADDR_SIZE(params->addr)))
        goto exit;

    BIO_set_fd(SSL_get_rbio(params->ssl), s, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(params->ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0,(struct sockaddr *)&params->addr);

    if (SSL_accept(params->ssl) <= 0) {
        while ((error = ERR_get_error()))
            debug(DBG_ERR, "dtlsservernew: SSL: %s", ERR_error_string(error, NULL));
        debug(DBG_ERR, "dtlsservernew: SSL_accept failed");
        goto exit;
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(SSL_get_rbio(params->ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    conf = find_clconf(handle, (struct sockaddr *)&params->addr, NULL);
    if (!conf)
        goto exit;

    cert = verifytlscert(params->ssl);
    if (!cert)
        goto exit;
    accepted_tls = conf->tlsconf;

    while (conf) {
        if (accepted_tls == conf->tlsconf && verifyconfcert(cert, conf)) {
            X509_free(cert);
            client = addclient(conf, 1);
            if (client) {
                client->sock = s;
                client->addr = addr_copy((struct sockaddr *)&params->addr);
                client->ssl = params->ssl;
                dtlsserverrd(client);
                removeclient(client);
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
    if (params->ssl) {
        SSL_shutdown(params->ssl);
        SSL_free(params->ssl);
    }
    if(s >= 0)
        close(s);
    free(params);
    debug(DBG_DBG, "dtlsservernew: exiting");
    pthread_exit(NULL);
}

int getConnectionInfo(int socket, struct sockaddr *from, socklen_t fromlen, struct sockaddr *to, socklen_t tolen) {
    uint8_t controlbuf[128];
    int offset = 0, ret, toaddrfound = 0;
    struct cmsghdr *ctrlhdr;
    struct msghdr msghdr;
    struct in6_pktinfo *info6;

    char tmp[48];

    msghdr.msg_name = from;
    msghdr.msg_namelen = fromlen;
    msghdr.msg_iov = NULL;
    msghdr.msg_iovlen = 0;
    msghdr.msg_control = controlbuf;
    msghdr.msg_controllen = sizeof(controlbuf);
    msghdr.msg_flags = 0;

    if ((ret = recvmsg(socket, &msghdr, MSG_PEEK | MSG_TRUNC)) < 0)
        return ret;

    debug(DBG_DBG, "udp packet from %s", addr2string(from));

    if (getsockname(socket, to, &tolen))
        return -1;
    while (offset < msghdr.msg_controllen) {
        ctrlhdr = (struct cmsghdr *)(controlbuf+offset);
        if(ctrlhdr->cmsg_level == IPPROTO_IP && ctrlhdr->cmsg_type == IP_PKTINFO) {
            debug(DBG_DBG, "udp packet to: %s", inet_ntop(AF_INET, &((struct in_pktinfo *)(ctrlhdr->__cmsg_data))->ipi_addr, tmp, sizeof(tmp)));

            ((struct sockaddr_in *)to)->sin_addr = ((struct in_pktinfo *)(ctrlhdr->__cmsg_data))->ipi_addr;
            toaddrfound = 1;
        } else if(ctrlhdr->cmsg_level == IPPROTO_IPV6 && ctrlhdr->cmsg_type == IPV6_RECVPKTINFO) {
            info6 = (struct in6_pktinfo *)ctrlhdr->__cmsg_data;
            debug(DBG_DBG, "udp packet to: %x", inet_ntop(AF_INET6, &info6->ipi6_addr, tmp, sizeof(tmp)));

            ((struct sockaddr_in6 *)to)->sin6_addr = info6->ipi6_addr;
            ((struct sockaddr_in6 *)to)->sin6_scope_id = info6->ipi6_ifindex;
            toaddrfound = 1;
        }
        offset += ctrlhdr->cmsg_len;
    }
    return toaddrfound ? ret : -1;
}

void *dtlslistener(void *arg) {
    int ndesc, s = *(int *)arg;
    unsigned char buf[4];
    struct sockaddr_storage from, to;
    struct dtlsservernewparams *params;
    struct pollfd fds[1];
    pthread_t dtlsserverth;
    BIO *bio;
    struct clsrvconf *conf;
    SSL *ssl;
    SSL_CTX *ctx;



    debug(DBG_DBG, "dtlslistener: starting");

    for (;;) {
        fds[0].fd = s;
        fds[0].events = POLLIN;
    	ndesc = poll(fds, 1, -1);
        if (ndesc < 0)
            continue;

        if (getConnectionInfo(s, (struct sockaddr *)&from, sizeof(from), (struct sockaddr *)&to, sizeof(to)) < 0) {
            debug(DBG_DBG, "udptlsserverrd: getConnectionInfo failed");
            continue;
        }

        conf = find_clconf(handle, (struct sockaddr *)&from, NULL);
        if (!conf) {
            debug(DBG_INFO, "udpdtlsserverrd: got UDP from unknown peer %s, ignoring", addr2string((struct sockaddr *)&from));
            recv(s, buf, 1, 0);
            continue;
        }

        pthread_mutex_lock(&conf->tlsconf->lock);
        if (!conf->tlsconf->dtlssslprep) {
            ctx = tlsgetctx(handle, conf->tlsconf);
            if (!ctx) {
                pthread_mutex_unlock(&conf->tlsconf->lock);
                continue;
            }
            ssl = SSL_new(ctx);
            if (!ssl) {
                pthread_mutex_unlock(&conf->tlsconf->lock);
                continue;
            }
            bio = BIO_new_dgram(s, BIO_NOCLOSE);
            SSL_set_bio(ssl, bio, bio);
            SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
            conf->tlsconf->dtlssslprep = ssl;
        } else {
            BIO_set_fd(SSL_get_rbio(conf->tlsconf->dtlssslprep), s, BIO_NOCLOSE);
        }

        if(DTLSv1_listen(ssl, &from)) {
            params = malloc(sizeof(struct dtlsservernewparams));
            memcpy(&params->addr, &from, sizeof(from));
            memcpy(&params->bind, &to, sizeof(to));
            params->ssl = conf->tlsconf->dtlssslprep;;
            if (!pthread_create(&dtlsserverth, &pthread_attr, dtlsservernew, (void *)params)) {
    		    pthread_detach(dtlsserverth);
                conf->tlsconf->dtlssslprep = NULL;
                pthread_mutex_unlock(&conf->tlsconf->lock);
                continue;
            } else {
                free(params);
            }
        }
        pthread_mutex_unlock(&conf->tlsconf->lock);
    }
    return NULL;
}

int dtlsconnect(struct server *server, struct timeval *when, int timeout, char *text) {
    struct timeval socktimeout, now, start = {0,0};
    time_t elapsed;
    X509 *cert;
    SSL_CTX *ctx = NULL;
    struct hostportres *hp;
    unsigned long error;
    BIO *bio;

    debug(DBG_DBG, "dtlsconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);

    if (server->state == RSP_SERVER_STATE_CONNECTED)
        server->state = RSP_SERVER_STATE_RECONNECTING;


    hp = (struct hostportres *)list_first(server->conf->hostports)->data;

    gettimeofday(&now, NULL);
    if (when && (now.tv_sec - when->tv_sec) < 60 )
        start.tv_sec = now.tv_sec - (60 - (now.tv_sec - when->tv_sec));

    for (;;) {
        /* ensure preioius connection is properly closed */
        if (server->ssl)
            SSL_shutdown(server->ssl);
        if (server->sock >= 0)
            close(server->sock);
        if (server->ssl)
            SSL_free(server->ssl);
        server->ssl = NULL;

        /* no sleep at startup or at first try */
        if (start.tv_sec) {
            gettimeofday(&now, NULL);
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
            pthread_mutex_lock(&server->lock);
            debug(DBG_INFO, "tlsconnect: retry connecting");
        } else {
            gettimeofday(&start, NULL);
        }
        /* done sleeping */

        debug(DBG_WARN, "dtlsconnect: trying to open DTLS connection to %s port %s", hp->host, hp->port);

        if ((server->sock = bindtoaddr(srcres, hp->addrinfo->ai_family, 0)) < 0)
            continue;
        if (connect(server->sock, hp->addrinfo->ai_addr, hp->addrinfo->ai_addrlen))
            continue;

        pthread_mutex_lock(&server->conf->tlsconf->lock);
        if (!(ctx = tlsgetctx(handle, server->conf->tlsconf))){
            pthread_mutex_unlock(&server->conf->tlsconf->lock);
            continue;
        }

        server->ssl = SSL_new(ctx);
        pthread_mutex_unlock(&server->conf->tlsconf->lock);
        if (!server->ssl)
            continue;

        bio = BIO_new_dgram(server->sock, BIO_CLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, hp->addrinfo->ai_addr);
        SSL_set_bio(server->ssl, bio, bio);
        if (SSL_connect(server->ssl) <= 0) {
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "tlsconnect: DTLS: %s", ERR_error_string(error, NULL));
            continue;
        }
        socktimeout.tv_sec = 5;
        socktimeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &socktimeout);

        debug(DBG_DBG, "dtlsconnect: DTLS: ok");

        cert = verifytlscert(server->ssl);
        if (!cert)
            continue;
        if (verifyconfcert(cert, server->conf)) {
            X509_free(cert);
            break;
        }
        X509_free(cert);
    }
    debug(DBG_WARN, "dtlsconnect: DTLS connection to %s port %s up", hp->host, hp->port);
    server->state = RSP_SERVER_STATE_CONNECTED;
    gettimeofday(&server->lastconnecttry, NULL);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

int clientradputdtls(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct clsrvconf *conf = server->conf;
    struct timespec timeout;

    timeout.tv_sec = 0;
    timeout.tv_nsec = 1000000;

    if (server->state != RSP_SERVER_STATE_CONNECTED)
        return 0;

    if (pthread_mutex_timedlock(&server->lock, &timeout))
        return 0;
    if (server->state != RSP_SERVER_STATE_CONNECTED) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }

    len = RADLEN(rad);
    while ((cnt = SSL_write(server->ssl, rad, len)) <= 0) {
        switch (SSL_get_error(server->ssl, cnt)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                while ((error = ERR_get_error()))
                    debug(DBG_ERR, "clientradputdtls: DTLS: %s", ERR_error_string(error, NULL));
                pthread_mutex_unlock(&server->lock);
                return 0;
        }
    }
    debug(DBG_DBG, "clientradputdtls: Sent %d bytes, Radius packet of length %d to DTLS peer %s", cnt, len, conf->name);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

void *dtlsclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf;
    struct timeval lastconnecttry;

    for (;;) {
	/* yes, lastconnecttry is really necessary */
	lastconnecttry = server->lastconnecttry;
    buf = raddtlsget(server->ssl, 5, &server->lock);
	if (!buf) {
        if(SSL_get_shutdown(server->ssl) || server->lostrqs) {
            if (server->lostrqs)
                debug (DBG_WARN, "dtlsclientrd: server %s did not respond, closing connection.", server->conf->name);
    	    dtlsconnect(server, &lastconnecttry, 0, "dtlsclientrd");
            server->lostrqs = 0;
        }
	    continue;
	}
	replyh(server, buf);
    }

    debug(DBG_INFO, "dtlsclientrd: exiting for %s", server->conf->name);
    pthread_mutex_lock(&server->lock);
    SSL_shutdown(server->ssl);
    close(server->sock);

    /* Wake up clientwr(). */
    server->clientrdgone = 1;
    pthread_mutex_lock(&server->newrq_mutex);
    pthread_cond_signal(&server->newrq_cond);
    pthread_mutex_unlock(&server->newrq_mutex);
    pthread_mutex_unlock(&server->lock);
    return NULL;
}

#else
const struct protodefs *dtlsinit(uint8_t h) {
    return NULL;
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
