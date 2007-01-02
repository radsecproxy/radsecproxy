/*
 * Copyright (C) 2006 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#define RADLEN(x) ntohs(((uint16_t *)(x))[1])

#define SOCKADDR_SIZE(addr) ((addr).ss_family == AF_INET ? \
                            sizeof(struct sockaddr_in) : \
                            sizeof(struct sockaddr_in6))

#define MAX_PEERS 256
/* MAX_REQUESTS is 256 due to Radius' 8 bit ID field */
#define MAX_REQUESTS 256
#define DEFAULT_TLS_SECRET "mysecret"
#define DEFAULT_UDP_PORT "1812"
#define DEFAULT_TLS_PORT "2083"

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

#define RAD_Attr_Type 0
#define RAD_Attr_Length 1
#define RAD_Attr_Value 2

/* requests that a client will send */
struct request {
    unsigned char *buf;
    uint8_t tries;
    uint8_t received;
    struct timeval timeout;
    struct peer *from;
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
    struct reply *replies;
    int count;
    int size;
    pthread_mutex_t count_mutex;
    pthread_cond_t count_cond;
};

struct peer {
    char type; /* U for UDP, T for TLS */
    char *host;
    char *port;
    char *secret;
    SSL *sslcl, *sslsrv;
    pthread_mutex_t lock;
    pthread_t clientth;
    int sockcl;
    struct addrinfo *addrinfo;
    /* requests and newrq* are requests passed from servers to clients */
    struct request *requests;
    uint8_t newrq;
    pthread_mutex_t newrq_mutex;
    pthread_cond_t newrq_cond;
    /* repl* are replies passed from clients to tls servers */
    struct replyq *replyq;
    int replycount;
    pthread_mutex_t replycount_mutex;
    pthread_cond_t replycount_cond;
};

void errx(char *format, ...);
void err(char *format, ...);
char *addr2string(struct sockaddr *addr, socklen_t len);
int bindport(int type, char *port);
int connectport(int type, char *host, char *port);
