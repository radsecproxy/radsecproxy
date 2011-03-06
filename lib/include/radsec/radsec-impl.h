/** @file libradsec-impl.h
    @brief Libraray internal header file for libradsec.  */

/* See the file COPYING for licensing information.  */

#include <freeradius/libradius.h>
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
    RS_CRED_TLS_PSK_RSA,	/* RFC 4279.  */
};
typedef unsigned int rs_cred_type_t;

#if defined (__cplusplus)
extern "C" {
#endif

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

struct rs_peer {		/* Config object for a connection.  */
    struct rs_connection *conn;
    struct rs_realm *realm;
    struct evutil_addrinfo *addr;
    char *secret;
    struct rs_peer *next;
};

struct rs_realm {	      /* Config object for a RADIUS realm.  */
    char *name;
    enum rs_conn_type type;
    int timeout;
    int retries;
    char *cacertfile;
    char *cacertpath;
    char *certfile;
    char *certkeyfile;
    struct rs_peer *peers;
    struct rs_realm *next;
};

struct rs_context {
    struct rs_realm *realms;
    struct rs_alloc_scheme alloc_scheme;
    struct rs_error *err;
    fr_randctx fr_randctx;
    cfg_t *cfg;
};

struct rs_connection {
    struct rs_context *ctx;
    struct rs_realm *realm;	/* Owned by ctx.  */
    struct event_base *evb;	/* Event base.  */
    struct event *tev;		/* Timeout event.  */
    struct rs_credentials transport_credentials;
    struct rs_conn_callbacks callbacks;
    void *user_data;
    struct rs_peer *peers;
    struct rs_peer *active_peer;
    struct rs_error *err;
    char is_connecting;		/* FIXME: replace with a single state member */
    char is_connected;		/* FIXME: replace with a single state member */
    int fd;			/* Socket.  */
    int tryagain;		/* For server failover.  */
    int nextid;			/* Next RADIUS packet identifier.  */
    int user_dispatch_flag : 1;	/* User does the dispatching.  */
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

struct rs_packet {
    struct rs_connection *conn;
    char hdr_read_flag;
    uint8_t hdr[4];
    RADIUS_PACKET *rpkt;
    struct rs_packet *original;
    char valid_flag;
    char written_flag;
    struct rs_packet *next;	/* Used for UDP output queue.  */
};

struct rs_attr {
    struct rs_packet *pkt;
    VALUE_PAIR *vp;
};

/* Nonpublic functions.  */
struct rs_error *_rs_resolv(struct evutil_addrinfo **addr,
			    rs_conn_type_t type, const char *hostname,
			    const char *service);
struct rs_peer *_rs_peer_create(struct rs_context *ctx,
				struct rs_peer **rootp);
struct rs_error *_rs_err_create(unsigned int code, const char *file,
				int line, const char *fmt, ...);
int _rs_err_conn_push_err(struct rs_connection *conn,
			  struct rs_error *err);


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

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
