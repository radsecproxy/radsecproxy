/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "tlv11.h"
#include "radmsg.h"

#define DEBUG_LEVEL 3

#define CONFIG_MAIN "/etc/radsecproxy.conf"

/* MAX_REQUESTS must be 256 due to Radius' 8 bit ID field */
#define MAX_REQUESTS 256
#define REQUEST_RETRY_INTERVAL 5
#define REQUEST_RETRY_COUNT 2
#define DUPLICATE_INTERVAL REQUEST_RETRY_INTERVAL * REQUEST_RETRY_COUNT
#define MAX_CERT_DEPTH 5
#define STATUS_SERVER_PERIOD 25
#define IDLE_TIMEOUT 300

#define RAD_UDP 0
#define RAD_TLS 1
#define RAD_TCP 2
#define RAD_DTLS 3

struct options {
    char **listenudp;
    char **listentcp;
    char **listentls;
    char **listendtls;
    char **listenaccudp;
    char *sourceudp;
    char *sourcetcp;
    char *sourcetls;
    char *sourcedtls;
    char *logdestination;
    uint8_t loglevel;
    uint8_t loopprevention;
};

struct request {
    struct timeval created;
    uint8_t refcount;
    uint8_t *buf, *replybuf;
    struct radmsg *msg;
    struct client *from;
    char *origusername;
    char origauth[16];
    uint8_t origid;
    int udpsock; /* only for UDP */
    uint16_t udpport; /* only for UDP */
};

/* requests that our client will send */
struct rqout {
    pthread_mutex_t *lock;
    struct request *rq;
    uint8_t tries;
    struct timeval expiry;
};

struct queue {
    struct list *entries;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct clsrvconf {
    char *name;
    uint8_t type; /* RAD_UDP/RAD_TLS/RAD_TCP */
    const struct protodefs *pdef;
    char *host;
    char *port;
    char *secret;
    char *tls;
    char *matchcertattr;
    regex_t *certcnregex;
    regex_t *certuriregex;
    char *confrewritein;
    char *confrewriteout;
    char *confrewriteusername;
    struct modattr *rewriteusername;
    char *dynamiclookupcommand;
    uint8_t statusserver;
    uint8_t retryinterval;
    uint8_t retrycount;
    uint8_t dupinterval;
    uint8_t certnamecheck;
    SSL_CTX *ssl_ctx;
    struct rewrite *rewritein;
    struct rewrite *rewriteout;
    struct addrinfo *addrinfo;
    uint8_t prefixlen;
    pthread_mutex_t *lock; /* only used for updating clients so far */
    struct list *clients;
    struct server *servers;
};

struct client {
    struct clsrvconf *conf;
    int sock; /* for tcp/dtls */
    SSL *ssl;
    pthread_mutex_t lock; /* used for updating rqs */
    struct request *rqs[MAX_REQUESTS];
    struct queue *replyq;
    struct queue *rbios; /* for dtls */
    struct sockaddr *addr;
};

struct server {
    struct clsrvconf *conf;
    int sock;
    SSL *ssl;
    pthread_mutex_t lock;
    pthread_t clientth;
    uint8_t clientrdgone;
    struct timeval lastconnecttry;
    struct timeval lastreply;
    uint8_t connectionok;
    uint8_t lostrqs;
    char *dynamiclookuparg;
    int nextid;
    struct timeval lastrcv;
    struct rqout *requests;
    uint8_t newrq;
    pthread_mutex_t newrq_mutex;
    pthread_cond_t newrq_cond;
    struct queue *rbios; /* for dtls */
};

struct realm {
    char *name;
    char *message;
    uint8_t accresp;
    regex_t regex;
    pthread_mutex_t subrealms_mutex;
    struct list *subrealms;
    struct list *srvconfs;
    struct list *accsrvconfs;
};

struct tls {
    char *name;
    char *cacertfile;
    char *cacertpath;
    char *certfile;
    char *certkeyfile;
    char *certkeypwd;
    uint8_t crlcheck;
    SSL_CTX *tlsctx;
    SSL_CTX *dtlsctx;
};

struct modattr {
    uint8_t t;
    char *replacement;
    regex_t *regex;
};

struct rewrite {
    uint8_t *removeattrs;
    uint32_t *removevendorattrs;
    struct list *addattrs;
    struct list *modattrs;
};

struct protodefs {
    char *name;
    char *secretdefault;
    uint8_t socktype;
    char *portdefault;
    uint8_t retrycountdefault;
    uint8_t retrycountmax;
    uint8_t retryintervaldefault;
    uint8_t retryintervalmax;
    uint8_t duplicateintervaldefault;
    void *(*listener)(void*);
    char **srcaddrport;
    int (*connecter)(struct server *, struct timeval *, int, char *);
    void *(*clientconnreader)(void*);
    int (*clientradput)(struct server *, unsigned char *);
    void (*addclient)(struct client *);
    void (*addserverextra)(struct clsrvconf *);
    void (*initextra)();
};

#define RADLEN(x) ntohs(((uint16_t *)(x))[1])

#define ATTRTYPE(x) ((x)[0])
#define ATTRLEN(x) ((x)[1])
#define ATTRVAL(x) ((x) + 2)
#define ATTRVALLEN(x) ((x)[1] - 2)

struct addrinfo *getsrcprotores(uint8_t type);
struct clsrvconf *find_clconf(uint8_t type, struct sockaddr *addr, struct list_node **cur);
struct clsrvconf *find_srvconf(uint8_t type, struct sockaddr *addr, struct list_node **cur);
struct clsrvconf *find_clconf_type(uint8_t type, struct list_node **cur);
struct client *addclient(struct clsrvconf *conf, uint8_t lock);
void removeclient(struct client *client);
void removeclientrqs(struct client *client);
struct queue *newqueue();
void removequeue(struct queue *q);
void freebios(struct queue *q);
struct request *newrequest();
void freerq(struct request *rq);
int radsrv(struct request *rq);
X509 *verifytlscert(SSL *ssl);
int verifyconfcert(X509 *cert, struct clsrvconf *conf);
void replyh(struct server *server, unsigned char *buf);
int connecttcp(struct addrinfo *addrinfo, struct addrinfo *src);
int bindtoaddr(struct addrinfo *addrinfo, int family, int reuse, int v6only);
