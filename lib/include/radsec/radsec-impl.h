/** @file libradsec-impl.h
    @brief Libraray internal header file for libradsec.  */

/* See the file COPYING for licensing information.  */

#include <freeradius/libradius.h>
#include <event2/util.h>

/* Constants.  */
#define RS_HEADER_LEN 4

/* Data types.  */
enum rs_cred_type {
    RS_CRED_NONE = 0,
    RS_CRED_TLS_PSK_RSA,	/* RFC 4279.  */
};
typedef unsigned int rs_cred_type_t;

struct rs_packet;

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

struct rs_handle {
    struct rs_alloc_scheme alloc_scheme;
    struct rs_error *err;
    fr_randctx fr_randctx;
    /* TODO: dictionary? */
};

struct rs_peer {
    struct rs_connection *conn;
    struct evutil_addrinfo *addr;
    int s;			/* Socket.  */
    char is_connecting;	/* FIXME: replace with a single state member */
    char is_connected;	/* FIXME: replace */
    char *secret;
    int timeout;		/* client only */
    int tries;			/* client only */
    struct rs_peer *next;
};

struct rs_connection {
    struct rs_handle *ctx;
    struct event_base *evb;
    struct bufferevent *bev;
    enum rs_conn_type type;
    struct rs_credentials transport_credentials;
    struct rs_conn_callbacks callbacks;
    struct rs_peer *peers;
    struct rs_peer *active_peer;
    struct rs_error *err;
};

struct rs_packet {
    struct rs_connection *conn;
    char hdr_read_flag;
    uint8_t hdr[4];
    RADIUS_PACKET *rpkt;
};

struct rs_attr {
    struct rs_packet *pkt;
    VALUE_PAIR *vp;
};

/* Convenience macros.  */
#define rs_calloc(h, nmemb, size) \
    (h->alloc_scheme.calloc ? h->alloc_scheme.calloc : calloc)(nmemb, size)
#define rs_malloc(h, size) \
    (h->alloc_scheme.malloc ? h->alloc_scheme.malloc : malloc)(size)
#define rs_free(h, ptr) \
    (h->alloc_scheme.free ? h->alloc_scheme.free : free)(ptr)
#define rs_realloc(h, realloc, ptr, size) \
    (h->alloc_scheme.realloc ? h->alloc_scheme.realloc : realloc)(ptr, size)

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
