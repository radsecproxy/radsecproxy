/** @file libradsec-impl.h
    @brief Libraray internal header file for libradsec.  */

/* Copyright 2010,2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#ifndef _RADSEC_RADSEC_IMPL_H_
#define _RADSEC_RADSEC_IMPL_H_ 1

#include <assert.h>
#include <event2/util.h>
#include <confuse.h>
#if defined(RS_ENABLE_TLS)
#include <openssl/ssl.h>
#endif
#include "compat.h"

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
};

struct rs_error {
    int code;
    char buf[1024];
};

enum rs_peer_type {
    RS_PEER_TYPE_CLIENT = 1,
    RS_PEER_TYPE_SERVER = 2
};

/** Configuration object for a connection.  */
struct rs_peer {
    enum rs_peer_type type;
    struct rs_connection *conn;
    struct rs_realm *realm;
    char *hostname;
    char *service;
    char *secret;               /* RADIUS secret.  */
    struct evutil_addrinfo *addr_cache;
    char *cacertfile;
    char *cacertpath;
    char *certfile;
    char *certkeyfile;
    struct rs_credentials *transport_cred;
    struct rs_peer *next;
};

/** Configuration object for a RADIUS realm.  */
struct rs_realm {
    char *name;
    enum rs_conn_type type;
    int timeout;
    int retries;
    struct rs_peer *peers;
    struct rs_realm *next;
};

/** Top configuration object.  */
struct rs_config {
    struct rs_realm *realms;
    cfg_t *cfg;
};

/** Libradsec context. */
struct rs_context {
    struct rs_config *config;
    struct rs_alloc_scheme alloc_scheme;
    struct rs_error *err;
    struct event_base *evb;	/* Event base.  */
};

enum rs_conn_subtype {
    RS_CONN_OBJTYPE_BASE = 1,
    RS_CONN_OBJTYPE_GENERIC,
    RS_CONN_OBJTYPE_LISTENER,
};
#define RS_CONN_MAGIC_BASE 0xAE004711u
#define RS_CONN_MAGIC_GENERIC 0x843AEF47u
#define RS_CONN_MAGIC_LISTENER 0xDCB04783u

/** Base class for a connection. */
struct rs_conn_base {
    uint32_t magic;             /* Must be one of RS_CONN_MAGIC_*. */
    struct rs_context *ctx;
    struct rs_realm *realm;	/* Owned by ctx.  */
    struct rs_peer *peers;      /*< Configured peers. */
    struct timeval timeout;
    int tryagain;		/* For server failover.  */
    void *user_data;
    struct rs_error *err;
    int fd;			/* Socket.  */
    /* TCP transport specifics.  */
    struct bufferevent *bev;	/* Buffer event.  */
    /* UDP transport specifics.  */
    struct event *wev;		/* Write event (for UDP).  */
    struct event *rev;		/* Read event (for UDP).  */
};

/** A "generic" connection. */
struct rs_connection {
    struct rs_conn_base base_;
    struct event *tev;		/* Timeout event.  */
    struct rs_conn_callbacks callbacks;
    struct rs_peer *active_peer;
    char is_connecting;		/* FIXME: replace with a single state member */
    char is_connected;		/* FIXME: replace with a single state member */
    struct rs_message *out_queue; /* Queue for outgoing UDP packets.  */
#if defined(RS_ENABLE_TLS)
    /* TLS specifics.  */
    SSL_CTX *tls_ctx;
    SSL *tls_ssl;
#endif
};

/** A listening connection. Spawns generic connections when peers
 * connect to it. */
struct rs_listener {
    struct rs_conn_base base_;
    struct evconnlistener *evlistener;
    struct rs_listener_callbacks callbacks;
};

enum rs_message_flags {
    RS_MESSAGE_HEADER_READ,
    RS_MESSAGE_RECEIVED,
    RS_MESSAGE_SENT,
};

struct radius_packet;

struct rs_message {
    struct rs_connection *conn;
    unsigned int flags;
    uint8_t hdr[RS_HEADER_LEN];
    struct radius_packet *rpkt;	/* FreeRADIUS object.  */
    struct rs_message *next;	/* Used for UDP output queue.  */
};

#if defined (__cplusplus)
}
#endif

/************************/
/* Convenience macros.  */

/* Memory allocation. */
#define rs_calloc(h, nmemb, size) ((h)->alloc_scheme.calloc != NULL \
     ? (h)->alloc_scheme.calloc : calloc)((nmemb), (size))
#define rs_malloc(h, size) ((h)->alloc_scheme.malloc != NULL \
     ? (h)->alloc_scheme.malloc : malloc)((size))
#define rs_free(h, ptr) ((h)->alloc_scheme.free != NULL \
     ? (h)->alloc_scheme.free : free)((ptr))
#define rs_realloc(h, ptr, size) ((h)->alloc_scheme.realloc != NULL \
     ? (h)->alloc_scheme.realloc : realloc)((ptr), (size))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

/* Basic CPP-based classes, proudly borrowed from Tor. */
#if defined(__GNUC__) && __GNUC__ > 3
 #define STRUCT_OFFSET(tp, member) __builtin_offsetof(tp, member)
#else
 #define STRUCT_OFFSET(tp, member) \
   ((off_t) (((char*)&((tp*)0)->member)-(char*)0))
#endif
#define SUBTYPE_P(p, subtype, basemember) \
  ((void*) (((char*)(p)) - STRUCT_OFFSET(subtype, basemember)))
#define DOWNCAST(to, ptr) ((to*)SUBTYPE_P(ptr, to, base_))
static struct rs_connection *TO_GENERIC_CONN (struct rs_conn_base *);
static struct rs_listener *TO_LISTENER_CONN (struct rs_conn_base *);
static INLINE struct rs_connection *TO_GENERIC_CONN (struct rs_conn_base *b)
{
  assert (b->magic == RS_CONN_MAGIC_GENERIC);
  return DOWNCAST (struct rs_connection, b);
}
static INLINE struct rs_listener *TO_LISTENER_CONN (struct rs_conn_base *b)
{
  assert (b->magic == RS_CONN_MAGIC_LISTENER);
  return DOWNCAST (struct rs_listener, b);
}

#endif /* _RADSEC_RADSEC_IMPL_H_ */

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
