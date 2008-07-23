/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#define DEBUG_LEVEL 3

#define CONFIG_MAIN "/etc/radsecproxy.conf"

/* MAX_REQUESTS must be 256 due to Radius' 8 bit ID field */
#define MAX_REQUESTS 256
#define REQUEST_RETRY_INTERVAL 5
#define REQUEST_RETRY_COUNT 2
#define MAX_CERT_DEPTH 5
#define STATUS_SERVER_PERIOD 25
#define IDLE_TIMEOUT 300
#define RAD_Access_Request 1
#define RAD_Access_Accept 2
#define RAD_Access_Reject 3
#define RAD_Accounting_Request 4
#define RAD_Accounting_Response 5
#define RAD_Access_Challenge 11
#define RAD_Status_Server 12
#define RAD_Status_Client 13

#define RAD_UDP 0
#define RAD_TLS 1
#define RAD_TCP 2

#define RAD_Attr_User_Name 1
#define RAD_Attr_User_Password 2
#define RAD_Attr_Reply_Message 18
#define RAD_Attr_Vendor_Specific 26
#define RAD_Attr_Calling_Station_Id 31
#define RAD_Attr_Tunnel_Password 69
#define RAD_Attr_Message_Authenticator 80

#define RAD_VS_ATTR_MS_MPPE_Send_Key 16
#define RAD_VS_ATTR_MS_MPPE_Recv_Key 17

struct options {
    char **listenudp;
    char **listentcp;
    char **listentls;
    char **listenaccudp;
    char *sourceudp;
    char *sourcetcp;
    char *logdestination;
    uint8_t loglevel;
    uint8_t loopprevention;
};

/* requests that our client will send */
struct request {
    unsigned char *buf;
    uint8_t tries;
    uint8_t received;
    struct timeval expiry;
    struct client *from;
    char *origusername;
    uint8_t origid; /* used by servwr */
    char origauth[16]; /* used by servwr */
    struct sockaddr_storage fromsa; /* used by udpservwr */
    int fromudpsock; /* used by udpservwr */
};

/* replies that a server will send */
struct reply {
    unsigned char *buf;
    struct sockaddr_storage tosa; /* used by udpservwr */
    int toudpsock; /* used by udpservwr */
};

struct replyq {
    struct list *replies;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct listenerarg {
    int s;
    uint8_t acconly;
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
    char *confrewrite;
    char *rewriteattr;
    regex_t *rewriteattrregex;
    char *rewriteattrreplacement;
    char *dynamiclookupcommand;
    uint8_t statusserver;
    uint8_t retryinterval;
    uint8_t retrycount;
    uint8_t certnamecheck;
    SSL_CTX *ssl_ctx;
    struct rewrite *rewrite;
    struct addrinfo *addrinfo;
    uint8_t prefixlen;
    struct list *clients;
    struct server *servers;
};

struct client {
    struct clsrvconf *conf;
    int s; /* for tcp */
    SSL *ssl;
    struct replyq *replyq;
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
    struct request *requests;
    uint8_t newrq;
    pthread_mutex_t newrq_mutex;
    pthread_cond_t newrq_cond;
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
    SSL_CTX *ctx;
};

struct rewrite {
    uint8_t *removeattrs;
    uint32_t *removevendorattrs;
};

struct rewriteconf {
    char *name;
    struct rewrite *rewrite;
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
    void *(*listener)(void*);
};

#define RADLEN(x) ntohs(((uint16_t *)(x))[1])

#define ATTRTYPE(x) ((x)[0])
#define ATTRLEN(x) ((x)[1])
#define ATTRVAL(x) ((x) + 2)
#define ATTRVALLEN(x) ((x)[1] - 2)

#define SOCKADDR_SIZE(addr) ((addr).ss_family == AF_INET ? \
                            sizeof(struct sockaddr_in) : \
                            sizeof(struct sockaddr_in6))
