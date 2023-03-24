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
int dtlsconnect(struct server *server, int timeout, int reconnect);
void *dtlsclientrd(void *arg);
int clientradputdtls(struct server *server, unsigned char *rad, int radlen);
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
    char tmp[INET6_ADDRSTRLEN], *subj;
    struct hostportres *hp;

    debug(DBG_WARN, "dtlsservernew: incoming DTLS connection from %s", addr2string((struct sockaddr *)&params->addr, tmp, sizeof(tmp)));

    conf = find_clconf(handle, (struct sockaddr *)&params->addr, NULL, &hp);
    if (!conf)
        goto exit;

    memset(&tmpsrvaddr, 0, sizeof(struct addrinfo));
    tmpsrvaddr.ai_addr = (struct sockaddr *)&params->bind;
    tmpsrvaddr.ai_addrlen = SOCKADDR_SIZE(params->bind);
    tmpsrvaddr.ai_family = params->bind.ss_family;
    tmpsrvaddr.ai_socktype = protodefs.socktype;

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
        if (accepted_tls == conf->tlsconf && verifyconfcert(cert, conf, NULL)) {
            subj = getcertsubject(cert);
            if(subj) {
                debug(DBG_WARN, "dtlsservernew: DTLS connection from %s, client %s, subject %s up",
                    addr2string((struct sockaddr *)&params->addr, tmp, sizeof(tmp)), conf->name, subj);
                free(subj);
            }
            X509_free(cert);
            client = addclient(conf, 1);
            if (client) {
                client->sock = s;
                client->addr = addr_copy((struct sockaddr *)&params->addr);
                client->ssl = params->ssl;
                tlsserverrd(client);
                removeclient(client);
            } else {
                debug(DBG_WARN, "dtlsservernew: failed to create new client instance");
            }
            goto exit;
        }
        conf = find_clconf(handle, (struct sockaddr *)&params->addr, &cur, &hp);
    }
    debug(DBG_WARN, "dtlsservernew: ignoring request, no matching TLS client for %s", 
        addr2string((struct sockaddr *)&params->addr, tmp, sizeof(tmp)));

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
    int ret;
    struct cmsghdr *ctrlhdr;
    struct msghdr msghdr;
    struct in6_pktinfo *info6;
    struct iovec iov[] = {{.iov_base = NULL, .iov_len = 0}};

    char tmp[48];

    msghdr.msg_name = from;
    msghdr.msg_namelen = fromlen;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = (sizeof(iov)/sizeof(*(iov)));
    msghdr.msg_control = controlbuf;
    msghdr.msg_controllen = sizeof(controlbuf);
    msghdr.msg_flags = 0;

    if ((ret = recvmsg(socket, &msghdr, MSG_PEEK | MSG_TRUNC)) < 0) {
        debug(DBG_ERR, "getConnectionInfo: recvmsg failed: %s", strerror(errno));
        return ret;
    }

    debug(DBG_DBG, "udp packet from: %s", addr2string(from, tmp, sizeof(tmp)));

    if (getsockname(socket, to, &tolen)) {
        debug(DBG_ERR, "getConnectionInfo: getsockname failed");
        return -1;
    }

    for (ctrlhdr = CMSG_FIRSTHDR(&msghdr); ctrlhdr; ctrlhdr = CMSG_NXTHDR(&msghdr, ctrlhdr)) {
#if defined(IP_PKTINFO)
        if(ctrlhdr->cmsg_level == IPPROTO_IP && ctrlhdr->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(ctrlhdr);
            debug(DBG_DBG, "udp packet to: %s", inet_ntop(AF_INET, &(pktinfo->ipi_addr), tmp, sizeof(tmp)));

            ((struct sockaddr_in *)to)->sin_addr = pktinfo->ipi_addr;
            return ret;
        }
#elif defined(IP_RECVDSTADDR)
        if(ctrlhdr->cmsg_level == IPPROTO_IP && ctrlhdr->cmsg_type == IP_RECVDSTADDR) {
            struct in_addr *addr = (struct in_addr *)CMSG_DATA(ctrlhdr);
            debug(DBG_DBG, "udp packet to: %s", inet_ntop(AF_INET, addr, tmp, sizeof(tmp)));

            ((struct sockaddr_in *)to)->sin_addr = *addr;
            return ret;
        }
#endif
        if(ctrlhdr->cmsg_level == IPPROTO_IPV6 && ctrlhdr->cmsg_type == IPV6_PKTINFO) {
            info6 = (struct in6_pktinfo *)CMSG_DATA(ctrlhdr);
            debug(DBG_DBG, "udp packet to: %s", inet_ntop(AF_INET6, &info6->ipi6_addr, tmp, sizeof(tmp)));

            ((struct sockaddr_in6 *)to)->sin6_addr = info6->ipi6_addr;
            ((struct sockaddr_in6 *)to)->sin6_scope_id = info6->ipi6_ifindex;
            return ret;
        }
    }

    debug(DBG_DBG, "getConnecitonInfo: unable to get destination address, using listen info instead");
    return ret;
}

void *dtlslistener(void *arg) {
    int ndesc, flags, s = *(int *)arg;
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
            sock_dgram_skip(s);
            continue;
        }

        conf = find_clconf(handle, (struct sockaddr *)&from, NULL, NULL);
        if (!conf) {
            debug(DBG_INFO, "dtlslistener: got UDP from unknown peer %s, ignoring", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));
            sock_dgram_skip(s);
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
                debug(DBG_ERR, "dtlslistener: failed to create SSL connection");
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
        } else {
            unsigned long error;
            while ((error = ERR_get_error()))
                debug(DBG_ERR, "dtlslistener: DTLS_listen failed: %s", ERR_error_string(error, NULL));
            debug(DBG_ERR, "dtlslistener: DTLS_listen failed or no cookie from %s", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));
        }
        pthread_mutex_unlock(&conf->tlsconf->lock);
    }
    return NULL;
}

static void cleanup_connection(struct server *server) {
    if (server->ssl)
        SSL_shutdown(server->ssl);
    if (server->sock >= 0)
        close(server->sock);
    server->sock = -1;
    if (server->ssl)
        SSL_free(server->ssl);
    server->ssl = NULL;
}

int dtlsconnect(struct server *server, int timeout, int reconnect) {
    struct timeval socktimeout, now, start;
    uint32_t wait;
    int firsttry = 1;
    X509 *cert;
    SSL_CTX *ctx = NULL;
    struct hostportres *hp;
    unsigned long error;
    BIO *bio;
    struct addrinfo *source = NULL;
    char *subj;
    struct list_node *entry;

    debug(DBG_DBG, "dtlsconnect: %s to %s", reconnect ? "reconnecting" : "initial connection", server->conf->name);
    pthread_mutex_lock(&server->lock);

    if (server->state == RSP_SERVER_STATE_CONNECTED)
        server->state = RSP_SERVER_STATE_RECONNECTING;

    pthread_mutex_unlock(&server->lock);

    if(server->conf->source) {
        source = resolvepassiveaddrinfo(server->conf->source, AF_UNSPEC, NULL, protodefs.socktype);
        if(!source)
            debug(DBG_WARN, "dtlsconnect: could not resolve source address to bind for server %s, using default", server->conf->name);
    }

    gettimeofday(&start, NULL);

    for (;;) {
        /* ensure previous connection is properly closed */
        cleanup_connection(server);

        wait = connect_wait(start, server->connecttime, firsttry);
        gettimeofday(&now, NULL);
        if (timeout && (now.tv_sec - start.tv_sec) + wait > timeout) {
            debug(DBG_DBG, "dtlsconnect: timeout");
            if (source) freeaddrinfo(source);
            return 0;
        }
        if (wait) debug(DBG_INFO, "Next connection attempt to %s in %lds", server->conf->name, wait);
        sleep(wait);
        firsttry = 0;

        for (entry = list_first(server->conf->hostports); entry; entry = list_next(entry)) {
            hp = (struct hostportres *)entry->data;
            debug(DBG_INFO, "dtlsconnect: trying to open DTLS connection to server %s (%s port %s)", server->conf->name, hp->host, hp->port);
            if ((server->sock = bindtoaddr(source ? source : srcres, hp->addrinfo->ai_family, 0)) < 0) {
                debug(DBG_ERR, "dtlsconnect: failed to bind socket for server %s (%s port %s)", server->conf->name, hp->host, hp->port);
                goto concleanup;
            }
            if (connect(server->sock, hp->addrinfo->ai_addr, hp->addrinfo->ai_addrlen)) {
                debug(DBG_ERR, "dtlsconnect: failed to connect socket for server %s (%s port %s)", server->conf->name, hp->host, hp->port);
                goto concleanup;
            }

            pthread_mutex_lock(&server->conf->tlsconf->lock);
            if (!(ctx = tlsgetctx(handle, server->conf->tlsconf))){
                pthread_mutex_unlock(&server->conf->tlsconf->lock);
                debug(DBG_ERR, "dtlsconnect: failed to get TLS context for server %s", server->conf->name);
                goto concleanup;
            }

            server->ssl = SSL_new(ctx);
            pthread_mutex_unlock(&server->conf->tlsconf->lock);
            if (!server->ssl) {
                debug(DBG_ERR, "dtlsconnect: failed to create SSL connection for server %s", server->conf->name);
                goto concleanup;
            }

            if (server->conf->sni) {
                struct in6_addr tmp;
                char *servername = server->conf->sniservername ? server->conf->sniservername : 
                    server->conf->servername ? server->conf->servername :
                    (inet_pton(AF_INET, hp->host, &tmp) || inet_pton(AF_INET6, hp->host, &tmp)) ? NULL : hp->host;
                if (servername && !tlssetsni(server->ssl, servername)) {
                    debug(DBG_ERR, "tlsconnect: set SNI %s failed", servername);
                    goto concleanup;
                }
            }

            bio = BIO_new_dgram(server->sock, BIO_CLOSE);
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, hp->addrinfo->ai_addr);
            if (server->conf->dtlsmtu) {
                SSL_set_options(server->ssl, SSL_OP_NO_QUERY_MTU);
                if (!DTLS_set_link_mtu(server->ssl, server->conf->dtlsmtu))
                    debug(DBG_WARN, "dtlsconnect: failed to set mtu %d", server->conf->dtlsmtu);
            }
            SSL_set_bio(server->ssl, bio, bio);
            if (sslconnecttimeout(server->ssl, 5) <= 0) {
                while ((error = ERR_get_error()))
                    debug(DBG_ERR, "dtlsconnect: SSL connect to %s failed: %s", server->conf->name, ERR_error_string(error, NULL));
                debug(DBG_ERR, "dtlsconnect: SSL connect to %s (%s port %s) failed", server->conf->name, hp->host, hp->port);
                goto concleanup;
            }
            socktimeout.tv_sec = 5;
            socktimeout.tv_usec = 0;
            if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &socktimeout) == -1)
                debug(DBG_WARN, "dtlsconnect: BIO_CTRL_DGRAM_SET_RECV_TIMEOUT failed");

            cert = verifytlscert(server->ssl);
            if (!cert) {
                debug(DBG_ERR, "tlsconnect: certificate verification failed for %s (%s port %s)", server->conf->name, hp->host, hp->port);
                goto concleanup;
            }

            if (verifyconfcert(cert, server->conf, hp)) {
                subj = getcertsubject(cert);
                if(subj) {
                    debug(DBG_WARN, "dtlsconnect: DTLS connection to %s (%s port %s), subject %s up", server->conf->name, hp->host, hp->port, subj);
                    free(subj);
                }
                X509_free(cert);
                break;
            } else {
                debug(DBG_ERR, "tlsconnect: certificate verification failed for %s (%s port %s)", server->conf->name, hp->host, hp->port);
            }
            X509_free(cert);

concleanup:
            /* ensure previous connection is properly closed */
            cleanup_connection(server);
        }
        if (server->ssl) break;
    }

    pthread_mutex_lock(&server->lock);
    server->state = RSP_SERVER_STATE_CONNECTED;
    gettimeofday(&server->connecttime, NULL);
    pthread_mutex_unlock(&server->lock);
    pthread_mutex_lock(&server->newrq_mutex);
    server->conreset = reconnect;
    pthread_cond_signal(&server->newrq_cond);
    pthread_mutex_unlock(&server->newrq_mutex);
    if (source) freeaddrinfo(source);
    return 1;
}

int clientradputdtls(struct server *server, unsigned char *rad, int radlen) {
    int cnt;
    struct clsrvconf *conf = server->conf;

    if (radlen <= 0) {
        debug(DBG_ERR, "clientradputdtls: invalid buffer (length)");
        return 0;
    }

    pthread_mutex_lock(&server->lock);
    if (server->state != RSP_SERVER_STATE_CONNECTED) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }

    if ((cnt = sslwrite(server->ssl, rad, radlen, 0)) <= 0 ) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }

    debug(DBG_DBG, "clientradputdtls: Sent %d bytes, Radius packet of length %zu to DTLS peer %s", cnt, radlen, conf->name);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

void *dtlsclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf = NULL;
    struct timeval now;
    int len = 0;

    for (;;) {
        len = radtlsget(server->ssl, server->conf->retryinterval * (server->conf->retrycount+1), &server->lock, &buf);
        if (!buf || !len) {
            if(SSL_get_shutdown(server->ssl) || (server->lostrqs && server->conf->statusserver!=RSP_STATSRV_OFF)) {
                if (SSL_get_shutdown(server->ssl))
                    debug (DBG_WARN, "tlscleintrd: connection to server %s lost", server->conf->name);
                else if (server->lostrqs)
                    debug (DBG_WARN, "dtlsclientrd: server %s did not respond, closing connection.", server->conf->name);
                if (server->dynamiclookuparg)
                    break;
                dtlsconnect(server, 0, 1);
                server->lostrqs = 0;
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
        replyh(server, buf, len);
        buf = NULL;
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
