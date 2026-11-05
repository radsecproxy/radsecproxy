/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2012,2016, NORDUnet A/S
 * Copyright (c) 2023, SWITCH
 * Copyright (c) 2026, Nova Labs
 * Copyright (c) 2026, CyB0rgg */
/* See LICENSE for licensing information. */

#ifndef _RADSECPROXY_H
#define _RADSECPROXY_H

#include "gconfig.h"
#include "hostport.h"
#include "list.h"
#include "radmsg.h"
#include "rewrite.h"
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <stdint.h>
#include <sys/time.h>

#include <openssl/asn1.h>

#define DEBUG_LEVEL 2

#define CONFIG_MAIN SYSCONFDIR "/radsecproxy.conf"

/* MAX_REQUESTS must be 256 due to Radius' 8 bit ID field */
#define MAX_REQUESTS 256
#define MAX_LOSTRQS 16
#define REQUEST_RETRY_INTERVAL 5
#define REQUEST_RETRY_COUNT 2
#define DUPLICATE_INTERVAL REQUEST_RETRY_INTERVAL *REQUEST_RETRY_COUNT
#define MAX_CERT_DEPTH 5
#define STATUS_SERVER_PERIOD 25
#define IDLE_TIMEOUT_DEFAULT 600
#define REVERSE_COA_TOKEN_LEN 16
#define REVERSE_COA_TOKEN_NASID 0   /* the value from the NAS-Identifier the nas sends */
#define REVERSE_COA_TOKEN_NASADDR 1 /* from its NAS-IP-Address or NAS-IPv6-Address */
#define REVERSE_COA_TOKEN_PEER 2    /* from the address its requests come from */
#define REVERSE_COA_TOKEN_KINDS 3
#define PSK_MIN_LENGTH 16
#define RSP_SECRET_LEN_WARN 12
/* Older OpenSSL API had a 256 byte limit; keep this limit to maximize compatibility*/
#define PSK_ID_MAX_LENGTH 256
#define RSP_TLS_REKEY_INTERVAL 3600

/* Target value for stack size.
 * Some platforms might define higher minimums in PTHREAD_STACK_MIN. */
#define THREAD_STACK_SIZE 32768

/* For systems that only support RFC 2292 Socket API, but not RFC 3542
 * like Cygwin */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/* 27262 is vendor DANTE Ltd. */
#define DEFAULT_TTL_ATTR "27262:1"
#define DEFAULT_FTICKS_PREFIX "F-TICKS/eduroam/1.0"

#define RAD_UDP 0
#define RAD_TLS 1
#define RAD_TCP 2
#define RAD_DTLS 3
#define RAD_PROTOCOUNT 4

enum rsp_fticks_reporting_type {
    RSP_FTICKS_REPORTING_NONE = 0, /* Default.  */
    RSP_FTICKS_REPORTING_BASIC,
    RSP_FTICKS_REPORTING_FULL
};

enum rsp_mac_type {
    RSP_MAC_STATIC = 0,
    RSP_MAC_ORIGINAL,
    RSP_MAC_VENDOR_HASHED,
    RSP_MAC_VENDOR_KEY_HASHED, /* Default.  */
    RSP_MAC_FULLY_HASHED,
    RSP_MAC_FULLY_KEY_HASHED
};

enum rsp_server_state {
    RSP_SERVER_STATE_STARTUP = 0, /* default */
    RSP_SERVER_STATE_BLOCKING_STARTUP,
    RSP_SERVER_STATE_CONNECTED,
    RSP_SERVER_STATE_RECONNECTING,
    RSP_SERVER_STATE_FAILING
};

enum rsp_statsrv {
    RSP_STATSRV_OFF = 0,
    RSP_STATSRV_ON,
    RSP_STATSRV_MINIMAL,
    RSP_STATSRV_AUTO
};

struct options {
    char *pidfile;
    char *logdestination;
    char *ftickssyslogfacility;
    char *fticksprefix;
    char *ttlattr;
    uint32_t ttlattrtype[2];
    uint8_t addttl;
    uint8_t loglevel;
    uint8_t logtid;
    uint8_t logfullusername;
    uint8_t loopprevention;
    enum rsp_mac_type log_mac;
    uint8_t *log_key;
    enum rsp_fticks_reporting_type fticks_reporting;
    enum rsp_mac_type fticks_mac;
    uint8_t *fticks_key;
    uint8_t ipv4only;
    uint8_t ipv6only;
    uint8_t sni;
    uint8_t verifyeap;
    uint8_t reqmsgauth;
    uint8_t protocolerror;
};

struct commonprotoopts {
    char **listenargs;
    char **sourcearg;
};

struct request {
    struct timeval created;
    uint32_t refcount;
    pthread_mutex_t refmutex;
    uint8_t *buf, *replybuf;
    int buflen, replybuflen;
    struct radmsg *msg;
    struct client *from;
    struct server *to;
    char *origusername;
    uint8_t rqid;
    uint8_t rqauth[16];
    uint8_t newid;
    int udpsock;                          /* only for UDP */
    struct sockaddr_storage *to_override; /* reverse coa to a udp client, else NULL */
    struct request *origin;               /* client request a reverse coa response answers */
    struct reverse_coa_plan *plan;        /* the candidates left for a reverse coa in flight, see reverse_coa.c */
};

/* requests that our client will send */
struct rqout {
    pthread_mutex_t *lock;
    struct request *rq;
    uint8_t tries;
    struct timeval expiry;
    uint8_t sentauth[16];
};

struct gqueue {
    struct list *entries;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct clsrvconf {
    uint8_t shallow;
    struct clsrvconf *parent;
    char *name;
    uint8_t type; /* RAD_UDP/RAD_TLS/RAD_TCP */
    const struct protodefs *pdef;
    char **hostsrc;
    char *servername;
    int hostaf;
    char *portsrc;
    struct list *hostports;
    char **source;
    uint8_t *secret;
    int secret_len;
    char *tls;
    char *pskid;
    uint8_t *pskkey;
    int pskkeylen;
    struct list *matchcertattrs;
    char **confmatchcertattrs;
    char *confrewritein;
    char *confrewriteout;
    char *confrewriteusername;
    struct modattr *rewriteusername;
    char *dynamiclookupcommand;
    enum rsp_statsrv statusserver;
    uint8_t retryinterval;
    uint8_t retrycount;
    uint8_t dupinterval;
    uint8_t certnamecheck;
    uint8_t certcncheck;
    uint8_t addttl;
    uint8_t keepalive;
    uint8_t loopprevention;
    uint8_t blockingstartup;
    int idletimeout;
    struct rewrite *rewritein;
    struct rewrite *rewriteout;
    pthread_mutex_t *lock;
    struct tls *tlsconf;
    struct list *clients;
    struct server *servers;
    char *fticks_viscountry;
    char *fticks_visinst;
    uint8_t sni;
    char *sniservername;
    long dtlsmtu;
    uint8_t reqmsgauth;
    uint8_t reqmsgauthproxy;
    uint8_t protocolerror;
    char **reverse_coa_realms;
    regex_t *reverse_coa_regexes; /* reverse_coa_realms compiled, see reverse_coa_compile_realms() */
    uint8_t accept_reverse_coa;
    char *nas_identifier;
    regex_t *nas_identifier_regex; /* NASidentifier given as /regexp/: every connection on the block is a nas */
    long reverse_coa_timeout;
    uint16_t coaport; /* reverse coa destination port for udp clients, default 3799 */
    uint8_t accept_coa;
    uint8_t add_operator_nas_id;
    uint8_t reverse_coa_fallback;
    uint8_t reverse_coa_sibling; /* another proxy of this site: a reverse coa for a nas not here is handed to it, one it hands here is never handed on */
};

#include "tlscommon.h"

struct reverse_coa_route;
struct reverse_coa_plan;

struct coa_dedup_slot {
    uint8_t occupied;
    uint8_t auth[16];
    time_t received;
    uint8_t *replybuf;
    int replybuflen;
    struct reverse_coa_route *route; /* where the request went, for retransmissions */
    uint8_t id;
};

struct client {
    struct clsrvconf *conf;
    int sock;
    SSL *ssl;
    pthread_mutex_t lock;
    struct request *rqs[MAX_REQUESTS];
    struct gqueue *replyq;
    struct sockaddr *addr;
    time_t expiry; /* for udp */
    struct timeval tlsnewkey;
    /* guards the reverse coa fields below and is never held across i/o: lock above is
       the connection's, a tls writer holds it across a blocking write */
    pthread_mutex_t reverse_coa_lock;
    struct rqout *reverse_coa_rqs; /* allocated on the first reverse coa sent */
    uint8_t reverse_coa_nextid;
    int reverse_coa_pending;
    struct reverse_coa_route *reverse_coa_route;
    char *identity;                        /* certificate subject, psk identity, or the block name */
    char token[REVERSE_COA_TOKEN_LEN + 1]; /* the value added in Operator-NAS-Identifier on the way up, naming the nas on this connection (learn_nas_identity()) */
    /* the values naming it by each name it has used, empty where not seen; a request carrying any of them reaches it */
    char tokens[REVERSE_COA_TOKEN_KINDS][REVERSE_COA_TOKEN_LEN + 1];
    time_t last_request;                   /* when this connection last sent a request (learn_nas_identity()) */
    /* what this connection says it is, for a NASidentifier /regexp/ block (learn_nas_identity()) */
    char nas_identifier_seen[256];
    uint8_t nas_identifier_seen_len;
    struct sockaddr_storage nas_addr_seen;
    uint8_t nas_addr_seen_set;
};

struct server {
    struct clsrvconf *conf;
    int sock;
    SSL *ssl;
    pthread_mutex_t lock;
    pthread_t clientth;
    uint8_t clientrdgone;
    struct timeval connecttime;
    struct timeval lastreply;
    struct timeval tlsnewkey;
    enum rsp_server_state state;
    uint8_t lostrqs;
    char *dynamiclookuparg;
    int nextid;
    struct timeval lastrcv;
    struct rqout *requests;
    uint8_t newrq;
    uint8_t conreset;
    pthread_mutex_t newrq_mutex;
    pthread_cond_t newrq_cond;
    struct coa_dedup_slot *reverse_coa_seen; /* only with acceptReverseCoA */
    pthread_mutex_t reverse_coa_lock;
    time_t last_dedup_cleanup;
};

struct realm {
    char *name;
    char *message;
    uint8_t accresp;
    uint8_t acclog;
    regex_t regex;
    uint32_t refcount;
    pthread_mutex_t refmutex;
    pthread_mutex_t mutex;
    struct realm *parent;
    struct list *subrealms;
    struct list *srvconfs;
    struct list *accsrvconfs;
    struct list *coasrvconfs;
};

struct protodefs {
    char *name;
    char *secretdefault;
    int socktype;
    char *portdefault;
    uint8_t retrycountdefault;
    uint8_t retrycountmax;
    uint8_t retryintervaldefault;
    uint8_t retryintervalmax;
    uint8_t duplicateintervaldefault;
    void (*setprotoopts)(struct commonprotoopts *);
    char **(*getlistenerargs)(void);
    void *(*listener)(void *);
    int (*connecter)(struct server *, int, int);
    void *(*clientconnreader)(void *);
    int (*clientradput)(struct server *, unsigned char *, int);
    void (*addclient)(struct client *);
    void (*addserverextra)(struct clsrvconf *);
    void (*setsrcres)(void);
    void (*initextra)(void);
};

struct clsrvconf *find_clconf(uint8_t type, struct sockaddr *addr, struct list_node **cur, struct hostportres **hp);
struct clsrvconf *find_srvconf(uint8_t type, struct sockaddr *addr, struct list_node **cur);
struct list *find_all_clconf(uint8_t type, struct sockaddr *addr, struct list_node *cur, struct hostportres **hp);
struct clsrvconf *find_clconf_type(uint8_t type, struct list_node **cur);
struct client *addclient(struct clsrvconf *conf, int sock,
                         const struct sockaddr *from, const char *identity, uint8_t lock);
void removelockedclient(struct client *client);
void removeclient(struct client *client);
pthread_mutex_t *removeclientrqs_sendrq_freeserver_lock(void);
struct gqueue *newqueue(void);
struct request *newrequest(void);
struct request *newrqref(struct request *rq);
int sendreply(struct request *rq);
int ensuremsgauthfront(struct radmsg *msg);
void freerq(struct request *rq);
int checkttl(struct radmsg *msg, uint32_t *attrtype);
int radsrv(struct request *rq);
int msgauthrequired(const struct clsrvconf *conf, struct radmsg *msg);
int recryptrequestattrs(struct radmsg *msg, struct clsrvconf *from, struct clsrvconf *to, uint8_t *rqauth);
struct realm *newrealmref(struct realm *r);
struct clsrvconf *choosesrvconf(struct list *srvconfs);
int addserver(struct clsrvconf *conf, const char *dynamiclookuparg);
int timeouth(struct server *server);
int closeh(struct server *server);
int replyh(struct server *server, uint8_t *buf, int buflen);
struct addrinfo *resolve_hostport_addrinfo(uint8_t type, char *hostport);
uint8_t *radattr2ascii(struct tlv *attr); /* TODO: mv this to radmsg? */
extern pthread_attr_t pthread_attr;

#endif /* _RADSECPROXY_H */

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
