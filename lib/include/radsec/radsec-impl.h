/** @file libradsec-impl.h
    @brief Libraray internal header file for libradsec.  */

/* Copyright 2010-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#ifndef _RADSEC_RADSEC_IMPL_H_
#define _RADSEC_RADSEC_IMPL_H_ 1

#include <event2/util.h>
#include <confuse.h>
#if defined(RS_ENABLE_TLS)
#include <openssl/ssl.h>
#endif

/* Constants.  */
#define RS_HEADER_LEN 4

/* Data types.  */
enum rs_cred_type {
    RS_CRED_NONE = 0,
    /* TLS pre-shared keys, RFC 4279.  */
    RS_CRED_TLS_PSK,
    /* RS_CRED_TLS_DH_PSK, */
    /* RS_CRED_TLS_RSA_PSK, */
};
typedef unsigned int rs_cred_type_t;

enum rs_key_encoding {
    RS_KEY_ENCODING_UTF8 = 1,
    RS_KEY_ENCODING_ASCII_HEX = 2,
};
typedef unsigned int rs_key_encoding_t;

#if defined (__cplusplus)
extern "C" {
#endif

struct rs_credentials {
    enum rs_cred_type type;
    char *identity;
    char *secret;
    enum rs_key_encoding secret_encoding;
    unsigned int secret_len;
};

struct rs_error {
    int code;
    char buf[1024];
};

/** Configuration object for a connection.  */
struct rs_peer {
    struct rs_connection *conn;
    struct rs_realm *realm;
    char *hostname;
    char *service;
    char *secret;               /* RADIUS secret.  */
    struct evutil_addrinfo *addr_cache;
    struct rs_peer *next;
};

/** Configuration object for a RADIUS realm.  */
struct rs_realm {
    char *name;
    enum rs_conn_type type;
    int timeout;
    int retries;
    char *cacertfile;
    char *cacertpath;
    char *certfile;
    char *certkeyfile;
    int disable_hostname_check;
    struct rs_credentials *transport_cred;
    struct rs_peer *peers;
    struct rs_realm *next;
};

/** Top configuration object.  */
struct rs_config {
    struct rs_realm *realms;
    cfg_t *cfg;
};

struct rs_context {
    struct rs_config *config;
    struct rs_alloc_scheme alloc_scheme;
    struct rs_error *err;
};

struct rs_connection {
    struct rs_context *ctx;
    struct rs_realm *realm;	/* Owned by ctx.  */
    struct event_base *evb;	/* Event base.  */
    struct event *tev;		/* Timeout event.  */
    struct rs_conn_callbacks callbacks;
    void *user_data;
    struct rs_peer *peers;
    struct rs_peer *active_peer;
    struct rs_error *err;
    struct timeval timeout;
    char is_connecting;		/* FIXME: replace with a single state member */
    char is_connected;		/* FIXME: replace with a single state member */
    int fd;			/* Socket.  */
    int tryagain;		/* For server failover.  */
    int nextid;			/* Next RADIUS packet identifier.  */
    /* TCP transport specifics.  */
    struct bufferevent *bev;	/* Buffer event.  */
    /* UDP transport specifics.  */
    struct event *wev;		/* Write event (for UDP).  */
    struct event *rev;		/* Read event (for UDP).  */
    struct rs_packet *out_queue; /* Queue for outgoing UDP packets.  */
#if defined(RS_ENABLE_TLS)
    /* TLS specifics.  */
    SSL_CTX *tls_ctx;
    SSL *tls_ssl;
#endif
};

enum rs_packet_flags {
    RS_PACKET_HEADER_READ,
    RS_PACKET_RECEIVED,
    RS_PACKET_SENT,
};

struct radius_packet;

struct rs_packet {
    struct rs_connection *conn;
    unsigned int flags;
    uint8_t hdr[RS_HEADER_LEN];
    struct radius_packet *rpkt;	/* FreeRADIUS object.  */
    struct rs_packet *next;	/* Used for UDP output queue.  */
};

#if defined (__cplusplus)
}
#endif

/* Convenience macros.  */
#define rs_calloc(h, nmemb, size) \
    (h->alloc_scheme.calloc ? h->alloc_scheme.calloc : calloc)(nmemb, size)
#define rs_malloc(h, size) \
    (h->alloc_scheme.malloc ? h->alloc_scheme.malloc : malloc)(size)
#define rs_free(h, ptr) \
    (h->alloc_scheme.free ? h->alloc_scheme.free : free)(ptr)
#define rs_realloc(h, realloc, ptr, size) \
    (h->alloc_scheme.realloc ? h->alloc_scheme.realloc : realloc)(ptr, size)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#endif /* _RADSEC_RADSEC_IMPL_H_ */

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
