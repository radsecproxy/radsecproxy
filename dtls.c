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
#include <fcntl.h>
#include "hash.h"
#include "radsecproxy.h"

#ifdef RADPROT_DTLS
#include "debug.h"
#include "util.h"
#include "hostport.h"

static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs();
void *dtlslistener(void *arg);
int dtlsconnect(struct server *server, int timeout, char *text);
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
    int len, cnt, sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
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
            if (cnt == 0)
                return cnt;

            pthread_mutex_lock(lock);
            if (cnt < 0 || fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                if (fds[0].revents & POLLERR) {
                    if(!getsockopt(BIO_get_fd(SSL_get_rbio(ssl), NULL), SOL_SOCKET, SO_ERROR, (void *)&sockerr, &errlen))
                        debug(DBG_INFO, "DTLS Connection lost: %s", strerror(sockerr));
                    else
                        debug(DBG_INFO, "DTLS Connection lost: unknown error");
                } else if (fds[0].revents & POLLHUP) {
                    debug(DBG_INFO, "DTLS Connection lost: hang up");
                } else if (fds[0].revents & POLLNVAL) {
                    debug(DBG_INFO, "DTLS Connection error: fd not open");
                }

                SSL_shutdown(ssl);
                pthread_mutex_unlock(lock);
                return -1;
            }
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
                    if (cnt == 0)
                        debug(DBG_INFO, "dtlsread: connection closed by remote host");
                    else {
                        debugerrno(errno, DBG_ERR, "dtlsread: connection lost");
                    }
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
    if (cnt < 1)
        return NULL;

    len = RADLEN(buf);
    if (len < 20) {
        debug(DBG_ERR, "raddtlsget: length too small, malformed packet! closing connection!");
        pthread_mutex_lock(lock);
        SSL_shutdown(ssl);
        pthread_mutex_unlock(lock);
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
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "dtlsserverwr: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));
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
            cnt, RADLEN(reply->replybuf), addr2string(client->addr, tmp, sizeof(tmp)));
        pthread_mutex_unlock(&client->lock);
        freerq(reply);
    }
}

void dtlsserverrd(struct client *client) {
    struct request *rq;
    uint8_t *buf;
    pthread_t dtlsserverwrth;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "dtlsserverrd: starting for %s", addr2string(client->addr, tmp, sizeof(tmp)));

    if (pthread_create(&dtlsserverwrth, &pthread_attr, dtlsserverwr, (void *)client)) {
	debug(DBG_ERR, "dtlsserverrd: pthread_create failed");
	return;
    }

    for (;;) {
	buf = raddtlsget(client->ssl, IDLE_TIMEOUT * 3, &client->lock);
	if (!buf) {
	    debug(DBG_ERR, "dtlsserverrd: connection from %s lost", addr2string(client->addr, tmp, sizeof(tmp)));
	    break;
	}
	debug(DBG_DBG, "dtlsserverrd: got Radius message from %s", addr2string(client->addr, tmp, sizeof(tmp)));
	rq = newrequest();
	if (!rq) {
	    free(buf);
	    continue;
	}
	rq->buf = buf;
	rq->from = client;
	if (!radsrv(rq)) {
	    debug(DBG_ERR, "dtlsserverrd: message authentication/validation failed, closing connection from %s", addr2string(client->addr, tmp, sizeof(tmp)));
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
    debug(DBG_DBG, "dtlsserverrd: reader for %s exiting", addr2string(client->addr, tmp, sizeof(tmp)));
}

void *dtlsservernew(void *arg) {
    struct dtlsservernewparams *params = (struct dtlsservernewparams *)arg;
    struct client *client;
    struct clsrvconf *conf;
    struct list_node *cur = NULL;
    X509 *cert = NULL;
    struct tls *accepted_tls = NULL;
    int s = -1;
    unsigned long error;
    struct timeval timeout;
    struct addrinfo tmpsrvaddr;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_WARN, "dtlsservernew: incoming DTLS connection from %s", addr2string((struct sockaddr *)&params->addr, tmp, sizeof(tmp)));

    conf = find_clconf(handle, (struct sockaddr *)&params->addr, NULL);
    if (!conf)
        goto exit;

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

    if (sslaccepttimeout(params->ssl, 30) <= 0) {
        while ((error = ERR_get_error()))
            debug(DBG_ERR, "dtlsservernew: SSL accept from %s failed: %s", conf->name, ERR_error_string(error, NULL));
        debug(DBG_ERR, "dtlsservernew: SSL_accept failed");
        goto exit;
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (BIO_ctrl(SSL_get_rbio(params->ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout) == -1)
        debug(DBG_WARN, "dtlsservernew: BIO_CTRL_DGRAM_SET_RECV_TIMEOUT failed");

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
    int ret, toaddrfound = 0;
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

    debug(DBG_DBG, "udp packet from %s", addr2string(from, tmp, sizeof(tmp)));

    if (getsockname(socket, to, &tolen))
        return -1;
    for (ctrlhdr = CMSG_FIRSTHDR(&msghdr); ctrlhdr; ctrlhdr = CMSG_NXTHDR(&msghdr, ctrlhdr)) {
#if defined(IP_PKTINFO)
        if(ctrlhdr->cmsg_level == IPPROTO_IP && ctrlhdr->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(ctrlhdr);
            debug(DBG_DBG, "udp packet to: %s", inet_ntop(AF_INET, &(pktinfo->ipi_addr), tmp, sizeof(tmp)));

            ((struct sockaddr_in *)to)->sin_addr = pktinfo->ipi_addr;
            toaddrfound = 1;
        }
#elif defined(IP_RECVDSTADDR)
        if(ctrlhdr->cmsg_level == IPPROTO_IP && ctrlhdr->cmsg_type == IP_RECVDSTADDR) {
            struct in_addr *addr = (struct in_addr *)CMSG_DATA(ctrlhdr);
            debug(DBG_DBG, "udp packet to: %s", inet_ntop(AF_INET, addr, tmp, sizeof(tmp)));

            ((struct sockaddr_in *)to)->sin_addr = *addr;
            toaddrfound = 1;
        }
#endif
        if(ctrlhdr->cmsg_level == IPPROTO_IPV6 && ctrlhdr->cmsg_type == IPV6_RECVPKTINFO) {
            info6 = (struct in6_pktinfo *)CMSG_DATA(ctrlhdr);
            debug(DBG_DBG, "udp packet to: %x", inet_ntop(AF_INET6, &info6->ipi6_addr, tmp, sizeof(tmp)));

            ((struct sockaddr_in6 *)to)->sin6_addr = info6->ipi6_addr;
            ((struct sockaddr_in6 *)to)->sin6_scope_id = info6->ipi6_ifindex;
            toaddrfound = 1;
        }
    }
    return toaddrfound ? ret : -1;
}

void *dtlslistener(void *arg) {
    int ndesc, flags, s = *(int *)arg;
    unsigned char buf[4];
    struct sockaddr_storage from, to;
    struct dtlsservernewparams *params;
    struct pollfd fds[1];
    pthread_t dtlsserverth;
    BIO *bio;
    struct clsrvconf *conf;
    SSL *ssl;
    SSL_CTX *ctx;
    char tmp[INET6_ADDRSTRLEN];

    debug(DBG_DBG, "dtlslistener: starting");

    if ((flags = fcntl(s,F_GETFL)) == -1)
        debugx(1, DBG_ERR, "dtlslistener: failed to get socket flags");
    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
        debugx(1, DBG_ERR, "dtlslistener: failed to set non-blocking");

    for (;;) {
        fds[0].fd = s;
        fds[0].events = POLLIN;
    	ndesc = poll(fds, 1, -1);
        if (ndesc < 0)
            continue;

        if (getConnectionInfo(s, (struct sockaddr *)&from, sizeof(from), (struct sockaddr *)&to, sizeof(to)) < 0) {
            debug(DBG_DBG, "dtlslistener: getConnectionInfo failed");
            continue;
        }

        conf = find_clconf(handle, (struct sockaddr *)&from, NULL);
        if (!conf) {
            debug(DBG_INFO, "dtlslistener: got UDP from unknown peer %s, ignoring", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));
            if (recv(s, buf, 4, 0) == -1)
                debug(DBG_ERR, "dtlslistener: recv failed - %s", strerror(errno));
            continue;
        }

        pthread_mutex_lock(&conf->tlsconf->lock);
        if (!conf->tlsconf->dtlssslprep) {
            debug(DBG_DBG, "dtlslistener: no cached ssl object for this context, create new");
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
            debug(DBG_DBG, "dtlslistener: reusing cached ssl object");
            BIO_set_fd(SSL_get_rbio(conf->tlsconf->dtlssslprep), s, BIO_NOCLOSE);
        }

#if (OPENSSL_VERSION_NUMBER < 0x10100000) || defined(LIBRESSL_VERSION_NUMBER)
        if(DTLSv1_listen(conf->tlsconf->dtlssslprep, &from) > 0) {
#else
        if(DTLSv1_listen(conf->tlsconf->dtlssslprep, (BIO_ADDR *)&from) > 0) {
#endif
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

int dtlsconnect(struct server *server, int timeout, char *text) {
    struct timeval socktimeout, now, start;
    time_t wait;
    int firsttry = 1;
    X509 *cert;
    SSL_CTX *ctx = NULL;
    struct hostportres *hp;
    unsigned long error;
    BIO *bio;
    struct addrinfo *source = NULL;

    debug(DBG_DBG, "dtlsconnect: called from %s", text);
    pthread_mutex_lock(&server->lock);

    if (server->state == RSP_SERVER_STATE_CONNECTED)
        server->state = RSP_SERVER_STATE_RECONNECTING;

    pthread_mutex_unlock(&server->lock);

    hp = (struct hostportres *)list_first(server->conf->hostports)->data;

    if(server->conf->source) {
        source = resolvepassiveaddrinfo(server->conf->source, AF_UNSPEC, NULL, protodefs.socktype);
        if(!source)
            debug(DBG_WARN, "dtlsconnect: could not resolve source address to bind for server %s, using default", server->conf->name);
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

        debug(DBG_INFO, "dtlsconnect: connecting to %s port %s", hp->host, hp->port);

        if ((server->sock = bindtoaddr(source ? source : srcres, hp->addrinfo->ai_family, 0)) < 0)
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
        if (sslconnecttimeout(server->ssl, 5) <= 0) {
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "dtlsconnect: SSL connect to %s failed: %s", server->conf->name, ERR_error_string(error, NULL));
            debug(DBG_ERR, "dtlsconnect: SSL connect to %s failed", server->conf->name, ERR_error_string(error, NULL));
            continue;
        }
        socktimeout.tv_sec = 5;
        socktimeout.tv_usec = 0;
        if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &socktimeout) == -1)
            debug(DBG_WARN, "dtlsconnect: BIO_CTRL_DGRAM_SET_RECV_TIMEOUT failed");

        cert = verifytlscert(server->ssl);
        if (!cert)
            continue;
        if (verifyconfcert(cert, server->conf)) {
            X509_free(cert);
            break;
        }
        X509_free(cert);
    }
    debug(DBG_WARN, "dtlsconnect: DTLS connection to %s up", server->conf->name);

    pthread_mutex_lock(&server->lock);
    server->state = RSP_SERVER_STATE_CONNECTED;
    gettimeofday(&server->connecttime, NULL);
    pthread_mutex_unlock(&server->lock);
    pthread_mutex_lock(&server->newrq_mutex);
    server->conreset = 1;
    pthread_cond_signal(&server->newrq_cond);
    pthread_mutex_unlock(&server->newrq_mutex);
    if (source) freeaddrinfo(source);
    return 1;
}

int clientradputdtls(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct clsrvconf *conf = server->conf;

    pthread_mutex_lock(&server->lock);
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

    for (;;) {
    buf = raddtlsget(server->ssl, server->conf->retryinterval * (server->conf->retrycount+1), &server->lock);
	if (!buf) {
        if(SSL_get_shutdown(server->ssl) || (server->lostrqs && server->conf->statusserver!=RSP_STATSRV_OFF)) {
            if (SSL_get_shutdown(server->ssl))
                debug (DBG_WARN, "tlscleintrd: connection to server %s lost", server->conf->name);
            else if (server->lostrqs)
                debug (DBG_WARN, "dtlsclientrd: server %s did not respond, closing connection.", server->conf->name);
    	    dtlsconnect(server, 0, "dtlsclientrd");
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
