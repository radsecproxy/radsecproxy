/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2012, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include "debug.h"
#include "hostport.h"
#include "radsecproxy.h"
#include "util.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef RADPROT_TLS

static void setprotoopts(struct commonprotoopts *opts);
static char **getlistenerargs(void);
void *tlslistener(void *arg);
int tlsconnect(struct server *server, int timeout, int reconnect);
void *tlsclientrd(void *arg);
int clientradputtls(struct server *server, unsigned char *rad, int radlen);
void tlssetsrcres(void);

static const struct protodefs protodefs = {
    "tls",
    "radsec",                                    /* secretdefault */
    SOCK_STREAM,                                 /* socktype */
    "2083",                                      /* portdefault */
    0,                                           /* retrycountdefault */
    0,                                           /* retrycountmax */
    REQUEST_RETRY_INTERVAL *REQUEST_RETRY_COUNT, /* retryintervaldefault */
    60,                                          /* retryintervalmax */
    DUPLICATE_INTERVAL,                          /* duplicateintervaldefault */
    setprotoopts,                                /* setprotoopts */
    getlistenerargs,                             /* getlistenerargs */
    tlslistener,                                 /* listener */
    tlsconnect,                                  /* connecter */
    tlsclientrd,                                 /* clientconnreader */
    clientradputtls,                             /* clientradput */
    NULL,                                        /* addclient */
    NULL,                                        /* addserverextra */
    tlssetsrcres,                                /* setsrcres */
    NULL                                         /* initextra */
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

static char **getlistenerargs(void) {
    return protoopts ? protoopts->listenargs : NULL;
}

void tlssetsrcres(void) {
    if (!srcres)
        srcres =
            resolvepassiveaddrinfo(protoopts ? protoopts->sourcearg : NULL,
                                   AF_UNSPEC, NULL, protodefs.socktype);
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

int tlsconnect(struct server *server, int timeout, int reconnect) {
    struct timeval now, start;
    uint32_t wait;
    int firsttry = 1;
    X509 *cert;
    SSL_CTX *ctx = NULL;
    unsigned long error;
    int origflags;
    struct addrinfo *source = NULL;
    char *subj;
    struct list_node *entry;
    struct hostportres *hp;

    debug(DBG_DBG, "tlsconnect: %s to %s", reconnect ? "reconnecting" : "initial connection", server->conf->name);
    pthread_mutex_lock(&server->lock);
    if (server->state == RSP_SERVER_STATE_CONNECTED)
        server->state = RSP_SERVER_STATE_RECONNECTING;
    pthread_mutex_unlock(&server->lock);

    if (server->conf->source) {
        source = resolvepassiveaddrinfo(server->conf->source, AF_UNSPEC, NULL, protodefs.socktype);
        if (!source)
            debug(DBG_WARN, "tlsconnect: could not resolve source address to bind for server %s, using default", server->conf->name);
    }

    gettimeofday(&start, NULL);

    for (;;) {
        cleanup_connection(server);
        wait = connect_wait(start, server->connecttime, firsttry);
        gettimeofday(&now, NULL);
        if (timeout && (now.tv_sec - start.tv_sec) + wait > timeout) {
            debug(DBG_DBG, "tlsconnect: timeout");
            if (source)
                freeaddrinfo(source);
            return 0;
        }
        if (wait)
            debug(DBG_INFO, "Next connection attempt to %s in %lds", server->conf->name, wait);
        sleep(wait);
        firsttry = 0;

        gettimeofday(&now, NULL);
        if (timeout && (now.tv_sec - start.tv_sec) > timeout) {
            debug(DBG_DBG, "tlsconnect: timeout");
            if (source)
                freeaddrinfo(source);
            return 0;
        }

        for (entry = list_first(server->conf->hostports); entry; entry = list_next(entry)) {
            hp = (struct hostportres *)entry->data;
            debug(DBG_INFO, "tlsconnect: trying to open TLS connection to server %s (%s port %s)", server->conf->name, hp->host, hp->port);
            if ((server->sock = connecttcp(hp->addrinfo, source ? source : srcres, list_count(server->conf->hostports) > 1 ? 5 : 30)) < 0) {
                debug(DBG_ERR, "tlsconnect: TLS connection to %s (%s port %s) failed: TCP connect failed", server->conf->name, hp->host, hp->port);
                goto concleanup;
            }

            if (server->conf->keepalive)
                enable_keepalive(server->sock);

            pthread_mutex_lock(&server->conf->tlsconf->lock);
            if (!(ctx = tlsgetctx(handle, server->conf->tlsconf))) {
                pthread_mutex_unlock(&server->conf->tlsconf->lock);
                debug(DBG_ERR, "tlsconnect: failed to get TLS context for server %s", server->conf->name);
                goto concleanup;
            }

            server->ssl = SSL_new(ctx);
            pthread_mutex_unlock(&server->conf->tlsconf->lock);
            if (!server->ssl) {
                debug(DBG_ERR, "tlsconnect: failed to create SSL connection for server %s", server->conf->name);
                goto concleanup;
            }

            if (!SSL_set_ex_data(server->ssl, RSP_EX_DATA_CONFIG, server->conf)) {
                debug(DBG_WARN, "tlsconnect: failed to set ex data");
            }

            if (server->conf->sni) {
                struct in6_addr tmp;
                char *servername = server->conf->sniservername                                                   ? server->conf->sniservername
                                   : server->conf->servername                                                    ? server->conf->servername
                                   : (inet_pton(AF_INET, hp->host, &tmp) || inet_pton(AF_INET6, hp->host, &tmp)) ? NULL
                                                                                                                 : hp->host;
                if (servername && !tlssetsni(server->ssl, servername)) {
                    debug(DBG_ERR, "tlsconnect: set SNI %s failed", servername);
                    goto concleanup;
                }
            }

            SSL_set_fd(server->ssl, server->sock);
            if (sslconnecttimeout(server->ssl, 5) <= 0) {
                while ((error = ERR_get_error()))
                    debug(DBG_ERR, "tlsconnect: SSL connect to %s failed: %s", server->conf->name, ERR_error_string(error, NULL));
                debug(DBG_ERR, "tlsconnect: SSL connect to %s (%s port %s) failed", server->conf->name, hp->host, hp->port);
                goto concleanup;
            }

            if (server->conf->pskid && server->conf->pskkey) {
                if (SSL_session_reused(server->ssl)) {
                    debug(DBG_WARN, "tlsconnect: TLS connection to %s (%s port %s), PSK identity %s with cipher %s up",
                          server->conf->name, hp->host, hp->port, server->conf->pskid, SSL_CIPHER_get_name(SSL_get_current_cipher(server->ssl)));
                    break;
                } else {
                    debug(DBG_ERR, "tlsconnect: TLS PSK set for %s (%s port %s) but not used in session, rejecting connection",
                          server->conf->name, hp->host, hp->port);
                    goto concleanup;
                }
            }

            cert = verifytlscert(server->ssl);
            if (!cert) {
                debug(DBG_ERR, "tlsconnect: certificate verification failed for %s (%s port %s)", server->conf->name, hp->host, hp->port);
                goto concleanup;
            }

            if (verifyconfcert(cert, server->conf, hp, server->dynamiclookuparg)) {
                subj = getcertsubject(cert);
                if (subj) {
                    debug(DBG_WARN, "tlsconnect: TLS connection to %s (%s port %s), subject %s, %s with cipher %s up",
                          server->conf->name, hp->host, hp->port, subj,
                          SSL_get_version(server->ssl), SSL_CIPHER_get_name(SSL_get_current_cipher(server->ssl)));
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
        if (server->ssl)
            break;
    }
    gettimeofday(&server->connecttime, NULL);
    server->tlsnewkey = server->connecttime;

    origflags = fcntl(server->sock, F_GETFL, 0);
    if (origflags == -1) {
        debugerrno(errno, DBG_WARN, "Failed to get flags");
    } else if (fcntl(server->sock, F_SETFL, origflags | O_NONBLOCK) == -1) {
        debugerrno(errno, DBG_WARN, "Failed to set O_NONBLOCK");
    }

    pthread_mutex_lock(&server->lock);
    server->state = RSP_SERVER_STATE_CONNECTED;
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

int clientradputtls(struct server *server, unsigned char *rad, int radlen) {
    int cnt;
    struct clsrvconf *conf = server->conf;
    struct timeval now;

    if (radlen <= 0) {
        debug(DBG_ERR, "clientradputtls: invalid buffer (length)");
        return 0;
    }

    pthread_mutex_lock(&server->lock);
    if (server->state != RSP_SERVER_STATE_CONNECTED) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }

    gettimeofday(&now, NULL);
#if OPENSSL_VERSION_NUMBER >= 0x10101000
    if (now.tv_sec - server->tlsnewkey.tv_sec > RSP_TLS_REKEY_INTERVAL && SSL_version(server->ssl) >= TLS1_3_VERSION) {
        debug(DBG_DBG, "clientradputtls: perform key update for long-running connection");
        if (SSL_get_key_update_type(server->ssl) == SSL_KEY_UPDATE_NONE &&
            !SSL_key_update(server->ssl, SSL_KEY_UPDATE_REQUESTED))
            debug(DBG_WARN, "clientradputtls: request for key update failed for %s", conf->name);
        server->tlsnewkey = now;
    }
#endif

    if ((cnt = sslwrite(server->ssl, rad, radlen, 0)) <= 0) {
        pthread_mutex_unlock(&server->lock);
        return 0;
    }

    debug(DBG_DBG, "clientradputtls: Sent %d bytes, Radius packet of length %zu to TLS peer %s", cnt, radlen, conf->name);
    pthread_mutex_unlock(&server->lock);
    return 1;
}

void *tlsclientrd(void *arg) {
    struct server *server = (struct server *)arg;
    unsigned char *buf = NULL;
    int len = 0;

    for (;;) {
        len = radtlsget(server->ssl, server->conf->retryinterval * (server->conf->retrycount + 1), &server->lock, &buf);
        if (buf && len > 0) {
            if (!replyh(server, buf, len))
                if (closeh(server))
                    break;
            buf = NULL;
        } else if (SSL_get_shutdown(server->ssl)) {
            if (closeh(server))
                break;
        } else {
            if (timeouth(server))
                break;
        }
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
    char tmp[INET6_ADDRSTRLEN], *subj;
    struct hostportres *hp;

    s = *(int *)arg;
    free(arg);
    if (getpeername(s, (struct sockaddr *)&from, &fromlen)) {
        debug(DBG_DBG, "tlsservernew: getpeername failed, exiting");
        goto exit;
    }
    debug(DBG_WARN, "tlsservernew: incoming TLS connection from %s", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));

    if (!(conf = find_clconf(handle, (struct sockaddr *)&from, &cur, &hp))) {
        debug(DBG_WARN, "tlsservernew: ignoring unknown TLS client %s", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));
        goto exit;
    }

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

    if (!SSL_set_ex_data(ssl, RSP_EX_DATA_CONFIG_LIST, find_all_clconf(handle, (struct sockaddr *)&from, cur, &hp))) {
        debug(DBG_WARN, "tlsservernew: failed to set ex data");
    }

    SSL_set_fd(ssl, s);
    if (sslaccepttimeout(ssl, 30) <= 0) {
        struct clsrvconf *selected = SSL_get_ex_data(ssl, RSP_EX_DATA_CONFIG);
        conf = selected ? selected : conf;
        while ((error = ERR_get_error()))
            debug(DBG_ERR, "tlsservernew: SSL accept from %s (%s) failed: %s", conf->name, addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)), ERR_error_string(error, NULL));
        debug(DBG_ERR, "tlsservernew: SSL_accept failed");
        list_free(SSL_get_ex_data(ssl, RSP_EX_DATA_CONFIG_LIST));
        goto exit;
    }
    list_free(SSL_get_ex_data(ssl, RSP_EX_DATA_CONFIG_LIST));

    if (!(SSL_session_reused(ssl) || (cert = verifytlscert(ssl))))
        goto exit;

    {
        struct clsrvconf *selected = SSL_get_ex_data(ssl, RSP_EX_DATA_CONFIG);
        conf = selected ? selected : conf;
    }

    accepted_tls = conf->tlsconf;

    origflags = fcntl(s, F_GETFL, 0);
    if (origflags == -1) {
        debugerrno(errno, DBG_WARN, "Failed to get flags");
    } else if (fcntl(s, F_SETFL, origflags | O_NONBLOCK) == -1) {
        debugerrno(errno, DBG_WARN, "Failed to set O_NONBLOCK");
    }

    if (SSL_session_reused(ssl)) {
        debug(DBG_WARN, "tlsservernew: TLS connection from %s, client %s, PSK identity %s wtih cipher %s up",
              addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)), conf->name, conf->pskid,
              SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
    } else {
        while (conf) {
            if (!conf->pskid && accepted_tls == conf->tlsconf && (verifyconfcert(cert, conf, NULL, NULL))) {
                subj = getcertsubject(cert);
                if (subj) {
                    debug(DBG_WARN, "tlsservernew: TLS connection from %s, client %s, subject %s, %s with cipher %s up",
                          addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)), conf->name, subj,
                          SSL_get_version(ssl), SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
                    free(subj);
                }
                X509_free(cert);
                cert = NULL;
                break;
            }
            conf = find_clconf(handle, (struct sockaddr *)&from, &cur, &hp);
        }
    }

    if (!conf) {
        debug(DBG_WARN, "tlsservernew: ignoring request, no matching TLS client for %s",
              addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));
        goto exit;
    }

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

exit:
    if (cert)
        X509_free(cert);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    shutdown(s, SHUT_RDWR);
    close(s);
    pthread_exit(NULL);
}

void tlsaccept(int s) {
    int *s_arg;
    pthread_t tcpserverth;

    s_arg = malloc(sizeof(s));
    if (!s_arg) {
        debug(DBG_ERR, "tlsaccept: malloc failed");
        return;
    }
    *s_arg = s;
    if (pthread_create(&tcpserverth, &pthread_attr, tlsservernew, (void *)s_arg)) {
        debug(DBG_ERR, "tlsaccept: pthread_create failed");
        free(s_arg);
        shutdown(s, SHUT_RDWR);
        close(s);
        return;
    }
    pthread_detach(tcpserverth);
}

void *tlslistener(void *arg) {
    accepttcp(*(int *)arg, tlsaccept);
    free(arg);
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
