/*
 * Copyright (C) 2006, 2007 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#define DEBUG_LEVEL 3

#define CONFIG_MAIN "/etc/radsecproxy.conf"

/* MAX_REQUESTS must be 256 due to Radius' 8 bit ID field */
#define MAX_REQUESTS 256
#define DEFAULT_TLS_SECRET "mysecret"
#define DEFAULT_UDP_PORT "1812"
#define DEFAULT_TLS_PORT "2083"
#define REQUEST_EXPIRY 20
#define REQUEST_RETRIES 3
#define MAX_CERT_DEPTH 5
#define STATUS_SERVER_PERIOD 25
#define RAD_Access_Request 1
#define RAD_Access_Accept 2
#define RAD_Access_Reject 3
#define RAD_Accounting_Request 4
#define RAD_Accounting_Response 5
#define RAD_Access_Challenge 11
#define RAD_Status_Server 12
#define RAD_Status_Client 13

#define RAD_Attr_User_Name 1
#define RAD_Attr_User_Password 2
#define RAD_Attr_Reply_Message 18
#define RAD_Attr_Vendor_Specific 26
#define RAD_Attr_Tunnel_Password 69
#define RAD_Attr_Message_Authenticator 80

#define RAD_VS_ATTR_MS_MPPE_Send_Key 16
#define RAD_VS_ATTR_MS_MPPE_Recv_Key 17

struct options {
    char *listenudp;
    char *listentcp;
    char *listenaccudp;
    char *sourceudp;
    char *sourcetcp;
    char *logdestination;
    uint8_t loglevel;
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
};

/* replies that a server will send */
struct reply {
    unsigned char *buf;
    struct sockaddr_storage tosa; /* used by udpservwr */
};

struct replyq {
    struct list *replies;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct clsrvconf {
    char *name;
    char type; /* U for UDP, T for TLS */
    char *host;
    char *port;
    char *secret;
    regex_t *certuriregex;
    regex_t *rewriteattrregex;
    char *rewriteattrreplacement;
    uint8_t statusserver;
    SSL_CTX *ssl_ctx;
    struct addrinfo *addrinfo;
    uint8_t prefixlen;
    struct list *clients;
    struct server *servers;
};

struct client {
    struct clsrvconf *conf;
    SSL *ssl;
    struct replyq *replyq;
    struct client *next;
};

struct server {
    struct clsrvconf *conf;
    int sock;
    SSL *ssl;
    pthread_mutex_t lock;
    pthread_t clientth;
    struct timeval lastconnecttry;
    uint8_t connectionok;
    uint8_t loststatsrv;
    int nextid;
    struct request *requests;
    uint8_t newrq;
    pthread_mutex_t newrq_mutex;
    pthread_cond_t newrq_cond;
};

struct realm {
    char *name;
    char *message;
    regex_t regex;
    struct list *srvconfs;
};

struct tls {
    char *name;
    SSL_CTX *ctx;
    int count;
};

#define RADLEN(x) ntohs(((uint16_t *)(x))[1])

#define ATTRTYPE(x) ((x)[0])
#define ATTRLEN(x) ((x)[1])
#define ATTRVAL(x) ((x) + 2)
#define ATTRVALLEN(x) ((x)[1] - 2)

#define SOCKADDR_SIZE(addr) ((addr).ss_family == AF_INET ? \
                            sizeof(struct sockaddr_in) : \
                            sizeof(struct sockaddr_in6))
