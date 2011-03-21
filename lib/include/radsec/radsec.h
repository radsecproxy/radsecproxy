/** \file radsec.h
    \brief Public interface for libradsec.  */

/* See the file COPYING for licensing information.  */

#include <unistd.h>
#include <sys/time.h>

#ifdef SYSCONFDIR
#define RS_FREERADIUS_DICT SYSCONFDIR "/raddb/dictionary"
#else  /* !SYSCONFDIR */
#define RS_FREERADIUS_DICT "/usr/local/raddb/dictionary"
#endif  /* !SYSCONFDIR */

enum rs_error_code {
    RSE_OK = 0,
    RSE_NOMEM = 1,
    RSE_NOSYS = 2,
    RSE_INVALID_CTX = 3,
    RSE_INVALID_CONN = 4,
    RSE_CONN_TYPE_MISMATCH = 5,
    RSE_FR = 6,			/* FreeRADIUS error.  */
    RSE_BADADDR = 7,
    RSE_NOPEER = 8,
    RSE_EVENT = 9,		/* libevent error.  */
    RSE_SOCKERR = 10,
    RSE_CONFIG = 11,
    RSE_BADAUTH = 12,
    RSE_INTERNAL = 13,
    RSE_SSLERR = 14,		/* OpenSSL error.  */
    RSE_INVALID_PKT = 15,
    RSE_TIMEOUT_CONN = 16,	/* Connection timeout.  */
    RSE_INVAL = 17,		/* Invalid argument.  */
    RSE_TIMEOUT_IO = 18,	/* I/O timeout.  */
    RSE_TIMEOUT = 19,		/* High level timeout.  */
    RSE_DISCO = 20,
};

enum rs_conn_type {
    RS_CONN_TYPE_NONE = 0,
    RS_CONN_TYPE_UDP,
    RS_CONN_TYPE_TCP,
    RS_CONN_TYPE_TLS,
    RS_CONN_TYPE_DTLS,
};
typedef unsigned int rs_conn_type_t;


#if defined (__cplusplus)
extern "C" {
#endif

/* Data types.  */
struct rs_context;		/* radsec-impl.h */
struct rs_connection;		/* radsec-impl.h */
struct rs_packet;		/* radsec-impl.h */
struct rs_conn;			/* radsec-impl.h */
struct rs_error;		/* radsec-impl.h */
struct rs_peer;			/* radsec-impl.h */
struct radius_packet;		/* <freeradius/libradius.h> */
struct event_base;		/* <event2/event-internal.h> */

typedef void *(*rs_calloc_fp) (size_t nmemb, size_t size);
typedef void *(*rs_malloc_fp) (size_t size);
typedef void (*rs_free_fp) (void *ptr);
typedef void *(*rs_realloc_fp) (void *ptr, size_t size);
struct rs_alloc_scheme {
    rs_calloc_fp calloc;
    rs_malloc_fp malloc;
    rs_free_fp free;
    rs_realloc_fp realloc;
};

typedef void (*rs_conn_connected_cb) (void *user_data /* FIXME: peer? */ );
typedef void (*rs_conn_disconnected_cb) (void *user_data /* FIXME: reason? */ );
typedef void (*rs_conn_packet_received_cb) (struct rs_packet *packet,
					    void *user_data);
typedef void (*rs_conn_packet_sent_cb) (void *user_data);
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


/* Function prototypes.  */

/*************/
/* Context.  */
/*************/
/** Create a context.  Freed by calling \a rs_context_destroy.  Note
    that the context must not be freed before all other libradsec
    objects have been freed.

    \a ctx Address of pointer to a struct rs_context.  This is the
    output of this function.

    \return RSE_OK (0) on success or RSE_NOMEM on out of memory.  */
int rs_context_create(struct rs_context **ctx);

/** Free a context.  Note that the context must not be freed before
    all other libradsec objects have been freed.  */
void rs_context_destroy(struct rs_context *ctx);

/** Initialize FreeRADIUS dictionary needed for creating packets.

    \a ctx Context.

    \a dict Optional string with full path to FreeRADIUS dictionary.
    If \a dict is NULL the path to the dictionary file is taken from
    the "dictionary" configuration directive.  Note that the
    configuration file must be read prior to using this option (see \a
    rs_context_read_config).

    \return RSE_OK (0) on success, RSE_NOMEM on memory allocation
    error and RSE_FR on FreeRADIUS error.  */
int rs_context_init_freeradius_dict(struct rs_context *ctx, const char *dict);

/** Set allocation scheme to use.  \a scheme is the allocation scheme
    to use, see \a rs_alloc_scheme.  \return On success, RSE_OK (0) is
    returned.  On error, !0 is returned and a struct \a rs_error is
    pushed on the error stack for the context.  The error can be
    accessed using \a rs_err_ctx_pop.  */
int rs_context_set_alloc_scheme(struct rs_context *ctx,
				struct rs_alloc_scheme *scheme);

/** Read configuration file. \a config_file is the path of the
    configuration file to read.  \return On success, RSE_OK (0) is
    returned.  On error, !0 is returned and a struct \a rs_error is
    pushed on the error stack for the context.  The error can be
    accessed using \a rs_err_ctx_pop.  */
int rs_context_read_config(struct rs_context *ctx, const char *config_file);

/****************/
/* Connection.  */
/****************/
/** Create a connection.  \a conn is the address of a pointer to an \a
    rs_connection, the output.  Free the connection using \a
    rs_conn_destroy.  Note that a connection must not be freed before
    all packets associated with the connection have been freed.  A
    packet is associated with a connection when it's created (\a
    rs_packet_create) or received (\a rs_conn_receive_packet).

    If \a config is not NULL it should be the name of a configuration
    found in the config file read in using \a rs_context_read_config.
    \return On success, RSE_OK (0) is returned.  On error, !0 is
    returned and a struct \a rs_error is pushed on the error stack for
    the context.  The error can be accessed using \a
    rs_err_ctx_pop.  */
int rs_conn_create(struct rs_context *ctx,
		   struct rs_connection **conn,
		   const char *config);

/** Not implemented.  */
int rs_conn_add_listener(struct rs_connection *conn,
			 rs_conn_type_t type,
			 const char *hostname,
			 int port);
/** Disconnect connection \a conn.  \return RSE_OK (0) on success, !0
 * on error.  On error, errno is set appropriately.  */
int rs_conn_disconnect (struct rs_connection *conn);

/** Disconnect and free memory allocated for connection \a conn.  Note
    that a connection must not be freed before all packets associated
    with the connection have been freed.  A packet is associated with
    a connection when it's created (\a rs_packet_create) or received
    (\a rs_conn_receive_packet).  \return RSE_OK (0) on success, !0 *
    on error.  On error, errno is set appropriately. */
int rs_conn_destroy(struct rs_connection *conn);

/** Set connection type for \a conn.  */
void rs_conn_set_type(struct rs_connection *conn, rs_conn_type_t type);

/** Not implemented.  */
int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb);

/** Register callbacks \a cb for connection \a conn.  */
void rs_conn_set_callbacks(struct rs_connection *conn,
			   struct rs_conn_callbacks *cb);

/** Remove callbacks for connection \a conn.  */
void rs_conn_del_callbacks(struct rs_connection *conn);

/** Return callbacks registered for connection \a conn.  \return
    Installed callbacks are returned.  */
struct rs_conn_callbacks *rs_conn_get_callbacks(struct rs_connection *conn);

/** Not implemented.  */
int rs_conn_select_peer(struct rs_connection *conn, const char *name);

/** Not implemented.  */
int rs_conn_get_current_peer(struct rs_connection *conn,
			     const char *name,
			     size_t buflen);

/** Special function used in blocking mode, i.e. with no callbacks
    registered.  For any other use of libradsec, a \a received_cb
    callback should be registered using \a rs_conn_set_callbacks.

    If \a req_msg is not NULL, a successfully received RADIUS message
    is verified against it.  If \a pkt_out is not NULL it will upon
    return contain a pointer to an \a rs_packet containing the new
    message.

    \return On error or if the connect (TCP only) or read times out,
    \a pkt_out will not be changed and one or more errors are pushed
    on \a conn (available through \a rs_err_conn_pop).  */
int rs_conn_receive_packet(struct rs_connection *conn,
			   struct rs_packet *request,
			   struct rs_packet **pkt_out);

/** Get the file descriptor associated with connection \a conn.
 * \return File descriptor.  */
int rs_conn_fd(struct rs_connection *conn);

/** Set the timeout value for connection \a conn.  */
void rs_conn_set_timeout(struct rs_connection *conn, struct timeval *tv);

/* Peer -- client and server.  */
int rs_peer_create(struct rs_connection *conn, struct rs_peer **peer_out);
int rs_peer_set_address(struct rs_peer *peer,
			const char *hostname,
			const char *service);
int rs_peer_set_secret(struct rs_peer *peer, const char *secret);
void rs_peer_set_timeout(struct rs_peer *peer, int timeout);
void rs_peer_set_retries(struct rs_peer *peer, int retries);

/************/
/* Packet.  */
/************/
/** Create a packet associated with connection \a conn.  */
int rs_packet_create(struct rs_connection *conn, struct rs_packet **pkt_out);

/** Free all memory allocated for packet \a pkt.  */
void rs_packet_destroy(struct rs_packet *pkt);

/** Send packet \a pkt on the connection associated with \a pkt.  \a
    user_data is sent to the \a rs_conn_packet_received_cb callback
    registered with the connection.  If no callback is registered with
    the connection, the event loop is run by \a rs_packet_send and it
    blocks until the packet has been succesfully sent.

    \return On success, RSE_OK (0) is returned.  On error, !0 is
    returned and a struct \a rs_error is pushed on the error stack for
    the connection.  The error can be accessed using \a
    rs_err_conn_pop.  */
int rs_packet_send(struct rs_packet *pkt, void *user_data);

/** Return the FreeRADIUS packet associated with packet \a pkt.  */
struct radius_packet *rs_packet_frpkt(struct rs_packet *pkt);

/** Create a RADIUS authentication request packet associated with
    connection \a conn.  Optionally, User-Name and User-Password
    attributes are added to the packet using the data in \a user_name
    and \a user_pw.  */
int rs_packet_create_authn_request(struct rs_connection *conn,
				   struct rs_packet **pkt,
				   const char *user_name,
				   const char *user_pw);

/************/
/* Config.  */
/************/
/** Find the realm named \a name in the configuration file previoiusly
    read in using \a rs_context_read_config.  */
struct rs_realm *rs_conf_find_realm(struct rs_context *ctx, const char *name);

/***********/
/* Error.  */
/***********/
/** Create a struct \a rs_error and push it on a FIFO associated with
    context \a ctx.  Note: The depth of the error stack is one (1) at
    the moment.  This will change in a future release.  */
int rs_err_ctx_push(struct rs_context *ctx, int code, const char *fmt, ...);
int rs_err_ctx_push_fl(struct rs_context *ctx,
		       int code,
		       const char *file,
		       int line,
		       const char *fmt,
		       ...);
/** Pop the first error from the error FIFO associated with context \a
    ctx or NULL if there are no errors in the FIFO.  */
struct rs_error *rs_err_ctx_pop(struct rs_context *ctx);

/** Create a struct \a rs_error and push it on a FIFO associated with
    connection \a conn.  Note: The depth of the error stack is one (1)
    at the moment.  This will change in a future release.  */
int rs_err_conn_push(struct rs_connection *conn,
		     int code,
		     const char *fmt,
		     ...);
int rs_err_conn_push_fl(struct rs_connection *conn,
			int code,
			const char *file,
			int line,
			const char *fmt,
			...);
/** Pop the first error from the error FIFO associated with connection
    \a conn or NULL if there are no errors in the FIFO.  */
struct rs_error *rs_err_conn_pop(struct rs_connection *conn);

int rs_err_conn_peek_code (struct rs_connection *conn);
void rs_err_free(struct rs_error *err);
char *rs_err_msg(struct rs_error *err);
int rs_err_code(struct rs_error *err, int dofree_flag);

#if defined (__cplusplus)
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
