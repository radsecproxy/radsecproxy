/** @file libradsec.h
    @brief Header file for libradsec.  */
/* See the file COPYING for licensing information.  */

#include <unistd.h>

enum rs_err_code {
    RSE_OK = 0,
    RSE_NOMEM = 1,
    RSE_NOSYS = 2,
    RSE_INVALID_CTX = 3,
    RSE_INVALID_CONN = 4,
    RSE_CONN_TYPE_MISMATCH = 5,
    RSE_FR = 6,
    RSE_BADADDR = 7,
    RSE_NOPEER = 8,
    RSE_EVENT = 9,
    RSE_CONNERR = 10,
    RSE_CONFIG = 11,
    RSE_BADAUTH = 12,
    RSE_SOME_ERROR = 21,
};

enum rs_conn_type {
    RS_CONN_TYPE_NONE = 0,
    RS_CONN_TYPE_UDP,
    RS_CONN_TYPE_TCP,
    RS_CONN_TYPE_TLS,
    RS_CONN_TYPE_DTLS,
};
typedef unsigned int rs_conn_type_t;


/* Data types.  */
struct rs_context;		/* radsec-impl.h */
struct rs_connection;		/* radsec-impl.h */
struct rs_packet;		/* radsec-impl.h */
struct rs_conn;			/* radsec-impl.h */
struct rs_attr;			/* radsec-impl.h */
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
typedef void (*rs_conn_disconnected_cb) (void *user_data
					 /* FIXME: reason? */ );
typedef void (*rs_conn_packet_received_cb) (const struct rs_packet *
					    packet, void *user_data);
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
/* Context.  */
int rs_context_create(struct rs_context **ctx, const char *dict);
void rs_context_destroy(struct rs_context *ctx);
int rs_context_set_alloc_scheme(struct rs_context *ctx,
				struct rs_alloc_scheme *scheme);
int rs_context_read_config(struct rs_context *ctx,
			   const char *config_file);

/* Connection.  */
int rs_conn_create(struct rs_context *ctx, struct rs_connection **conn,
		   const char *config);
void rs_conn_set_type(struct rs_connection *conn, rs_conn_type_t type);
int rs_conn_add_listener(struct rs_connection *conn, rs_conn_type_t type,
			 const char *hostname, int port);
void rs_conn_destroy(struct rs_connection *conn);
int rs_conn_set_eventbase(struct rs_connection *conn,
			  struct event_base *eb);
int rs_conn_set_callbacks(struct rs_connection *conn,
			  struct rs_conn_callbacks *cb);
struct rs_conn_callbacks *rs_conn_get_callbacks(struct rs_connection
						*conn);
int rs_conn_select_server(struct rs_connection *conn, const char *name);
int rs_conn_get_current_server(struct rs_connection *conn,
			       const char *name, size_t buflen);
int rs_conn_receive_packet(struct rs_connection *conn,
			   struct rs_packet *request,
			   struct rs_packet **pkt_out);
int rs_conn_fd(struct rs_connection *conn);

/* Server and client.  */
int rs_server_create(struct rs_connection *conn, struct rs_peer **server);
int rs_server_set_address(struct rs_peer *server, const char *hostname,
			  const char *service);
int rs_server_set_secret(struct rs_peer *server, const char *secret);
void rs_server_set_timeout(struct rs_peer *server, int timeout);
void rs_server_set_tries(struct rs_peer *server, int tries);

/* Packet.  */
int rs_packet_create_acc_request(struct rs_connection *conn,
				 struct rs_packet **pkt,
				 const char *user_name,
				 const char *user_pw);
void rs_packet_destroy(struct rs_packet *pkt);
void rs_packet_add_attr(struct rs_packet *pkt, struct rs_attr *attr);
int rs_packet_send(struct rs_packet *pkt, void *data);
struct radius_packet *rs_packet_frpkt(struct rs_packet *pkt);

/* Attribute.  */
/* FIXME: Replace (or complement) with a wrapper for paircreate().  */
int rs_attr_create(struct rs_connection *conn, struct rs_attr **attr,
		   const char *type, const char *val);
void rs_attr_destroy(struct rs_attr *attr);

/* Config.  */
struct rs_realm *rs_conf_find_realm(struct rs_context *ctx,
				    const char *name);

/* Error.  */
int rs_err_ctx_push(struct rs_context *ctx, int code, const char *fmt,
		    ...);
int rs_err_ctx_push_fl(struct rs_context *ctx, int code, const char *file,
		       int line, const char *fmt, ...);
struct rs_error *rs_err_ctx_pop(struct rs_context *ctx);
int rs_err_conn_push(struct rs_connection *conn, int code, const char *fmt,
		     ...);
int rs_err_conn_push_fl(struct rs_connection *conn, int code,
			const char *file, int line, const char *fmt, ...);
struct rs_error *rs_err_conn_pop(struct rs_connection *conn);
void rs_err_free(struct rs_error *err);
char *rs_err_msg(struct rs_error *err, int dofree_flag);
int rs_err_code(struct rs_error *err, int dofree_flag);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
