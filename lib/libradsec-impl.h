/** @file libradsec-impl.h
    @brief Libraray internal header file for libradsec.  */

/* See the file COPYING for licensing information.  */

#include <freeradius/libradius.h>

/* Constants.  */
#define RS_HEADER_LEN 4

/* Data types.  */
enum rs_cred_type {
    RS_CRED_NONE = 0,
    RS_CRED_TLS_PSK_RSA,	/* RFC 4279.  */
};
typedef unsigned int rs_cred_type_t;

struct rs_credentials {
    enum rs_cred_type type;
    char *identity;
    char *secret;
};

struct rs_error {
    int code;
    char *msg;
    char buf[1024];
};

typedef void * (*rs_calloc_fp)(size_t nmemb, size_t size);
typedef void * (*rs_malloc_fp)(size_t size);
typedef void (*rs_free_fp)(void *ptr);
typedef void * (*rs_realloc_fp)(void *ptr, size_t size);
struct rs_alloc_scheme {
    rs_calloc_fp calloc;
    rs_malloc_fp malloc;
    rs_free_fp free;
    rs_realloc_fp realloc;
};

typedef void (*rs_conn_connected_cb)(void *user_data /* FIXME: peer? */);
typedef void (*rs_conn_disconnected_cb)(void *user_data /* FIXME: reason? */);
typedef void (*rs_conn_packet_received_cb)(const struct rs_packet *packet,
					   void *user_data);
typedef void (*rs_conn_packet_sent_cb)(void *user_data);

/** Connection callbacks.  */
struct rs_conn_callbacks {
    /** Callback invoked when the connection has been established.  */
    rs_conn_connected_cb connected_cb;
    /** Callback invoked when the connection has been torn down.  */
    rs_conn_disconnected_cb disconnected_cb;
    /** Callback invoked when a packet was received.  */
    rs_conn_packet_received_cb received_cb;
    /** Callback invoked when a packet was successfully sent.  */
    rs_conn_packet_sent_cb sent_cb;
};

struct rs_handle {
    struct rs_alloc_scheme alloc_scheme;
    struct rs_error *err;
    fr_randctx fr_randctx;

    /* TODO: dictionary? */
};

struct rs_peer {
    struct addrinfo addr;
    char *secret;
    int timeout;		/* client only */
    int tries;			/* client only */
};

struct rs_connection {
    struct rs_handle *ctx;
    enum rs_conn_type conn_type;
    struct rs_credentials transport_credentials;
    struct rs_conn_callbacks callbacks;
    struct rs_error *err;
    struct rs_peer *peer;
};

struct rs_packet {
    struct rs_connection *conn;
    RADIUS_PACKET *rpkt;
};

struct rs_attr {
    struct rs_packet *pkt;
    VALUE_PAIR *vp;
};


/* Convenience macros.  */
#define rs_calloc(ctx, nmemb, size) \
    (ctx->alloc_scheme.calloc ? ctx->alloc_scheme.calloc : calloc)(nmemb, size)
#define rs_malloc(ctx, size) \
    (ctx->alloc_scheme.malloc ? ctx->alloc_scheme.malloc : malloc)(size)
#define rs_free(ctx, ptr) \
    (ctx->alloc_scheme.free ? ctx->alloc_scheme.free : free)(ptr)
#define rs_(ctx, realloc, ptr, size) \
    (ctx->alloc_scheme.realloc ? ctx->alloc_scheme.realloc : realloc)(ptr, size)

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
