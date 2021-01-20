/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2012,2016, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <sys/time.h>
#include <stdint.h>
#include <pthread.h>
#include <regex.h>
#include <netinet/in.h>
#include "list.h"
#include "radmsg.h"
#include "gconfig.h"
#include "rewrite.h"

#include <openssl/asn1.h>

#define DEBUG_LEVEL 2

#define CONFIG_MAIN SYSCONFDIR"/radsecproxy.conf"

/* MAX_REQUESTS must be 256 due to Radius' 8 bit ID field */
#define MAX_REQUESTS 256
#define MAX_LOSTRQS 16
#define REQUEST_RETRY_INTERVAL 5
#define REQUEST_RETRY_COUNT 2
#define DUPLICATE_INTERVAL REQUEST_RETRY_INTERVAL * REQUEST_RETRY_COUNT
#define MAX_CERT_DEPTH 5
#define STATUS_SERVER_PERIOD 25
#define IDLE_TIMEOUT 300

/* We want PTHREAD_STACK_SIZE to be 32768, but some platforms
 * have a higher minimum value defined in PTHREAD_STACK_MIN. */
#define PTHREAD_STACK_SIZE 32768
#if defined(PTHREAD_STACK_MIN)
#if PTHREAD_STACK_MIN > PTHREAD_STACK_SIZE
#undef PTHREAD_STACK_SIZE
#define PTHREAD_STACK_SIZE PTHREAD_STACK_MIN
#endif
#endif

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
    struct radmsg *msg;
    struct client *from;
    struct server *to;
    char *origusername;
    uint8_t rqid;
    uint8_t rqauth[16];
    uint8_t newid;
    int udpsock; /* only for UDP */
};

/* requests that our client will send */
struct rqout {
    pthread_mutex_t *lock;
    struct request *rq;
    uint8_t tries;
    struct timeval expiry;
};

struct gqueue {
    struct list *entries;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct clsrvconf {
    char *name;
    uint8_t type; /* RAD_UDP/RAD_TLS/RAD_TCP */
    const struct protodefs *pdef;
    char **hostsrc;
    int hostaf;
    char *portsrc;
    struct list *hostports;
    char **source;
    char *confsecret;
    uint8_t *secret;
    int secret_len;
    char *tls;
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
    uint8_t addttl;
    uint8_t keepalive;
    uint8_t loopprevention;
    struct rewrite *rewritein;
    struct rewrite *rewriteout;
    pthread_mutex_t *lock; /* only used for updating clients so far */
    struct tls *tlsconf;
    struct list *clients;
    struct server *servers;
    char *fticks_viscountry;
    char *fticks_visinst;
};

#include "tlscommon.h"

struct client {
    struct clsrvconf *conf;
    int sock;
    SSL *ssl;
	pthread_mutex_t lock;
    struct request *rqs[MAX_REQUESTS];
    struct gqueue *replyq;
    struct sockaddr *addr;
    time_t expiry; /* for udp */
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
};

struct realm {
    char *name;
    char *message;
    uint8_t accresp;
    regex_t regex;
    uint32_t refcount;
    pthread_mutex_t refmutex;
    pthread_mutex_t mutex;
    struct realm *parent;
    struct list *subrealms;
    struct list *srvconfs;
    struct list *accsrvconfs;
    struct list *dynauthsrvconfs;
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
    char **(*getlistenerargs)();
    void *(*listener)(void*);
    int (*connecter)(struct server *, int, char *);
    void *(*clientconnreader)(void*);
    int (*clientradput)(struct server *, unsigned char *);
    void (*addclient)(struct client *);
    void (*addserverextra)(struct clsrvconf *);
    void (*setsrcres)();
    void (*initextra)();
};

#define RADLEN(x) ntohs(((uint16_t *)(x))[1])

struct clsrvconf *find_clconf(uint8_t type, struct sockaddr *addr, struct list_node **cur);
struct clsrvconf *find_srvconf(uint8_t type, struct sockaddr *addr, struct list_node **cur);
struct clsrvconf *find_clconf_type(uint8_t type, struct list_node **cur);
struct client *addclient(struct clsrvconf *conf, uint8_t lock);
void removelockedclient(struct client *client);
void removeclient(struct client *client);
struct gqueue *newqueue();
struct request *newrequest();
void freerq(struct request *rq);
int radsrv(struct request *rq);
void replyh(struct server *server, unsigned char *buf);
struct addrinfo *resolve_hostport_addrinfo(uint8_t type, char *hostport);
uint8_t *radattr2ascii(struct tlv *attr); /* TODO: mv this to radmsg? */
extern pthread_attr_t pthread_attr;

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
