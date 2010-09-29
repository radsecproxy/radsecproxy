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
struct rs_handle;		/* radsec-impl.h */
struct rs_alloc_scheme;		/* radsec-impl.h */
struct rs_connection;		/* radsec-impl.h */
struct rs_conn_callbacks;	/* radsec-impl.h */
struct rs_packet;		/* radsec-impl.h */
struct rs_conn;			/* radsec-impl.h */
struct rs_attr;			/* radsec-impl.h */
struct rs_error;		/* radsec-impl.h */
struct rs_peer;			/* radsec-impl.h */
struct event_base;		/* <event.h> */

/* Function prototypes.  */
int rs_context_create(struct rs_handle **ctx, const char *dict);
void rs_context_destroy(struct rs_handle *ctx);
int rs_context_set_alloc_scheme(struct rs_handle *ctx, struct rs_alloc_scheme *scheme);
int rs_context_config_read(struct rs_handle *ctx, const char *config_file);

int rs_conn_create(struct rs_handle *ctx, struct rs_connection **conn);
int rs_conn_add_server(struct rs_connection *conn, struct rs_peer **server, rs_conn_type_t type, const char *hostname, int port);
int rs_conn_add_listener(struct rs_connection  *conn, rs_conn_type_t type, const char *hostname, int port);
void rs_conn_destroy(struct rs_connection  *conn);
int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb);
int rs_conn_set_callbacks(struct rs_connection *conn, struct rs_conn_callbacks *cb);
int rs_conn_select_server(struct rs_connection *conn, const char *name);
int rs_conn_get_current_server(struct rs_connection *conn, const char *name, size_t buflen);

void rs_server_set_timeout(struct rs_peer *server, int timeout);
void rs_server_set_tries(struct rs_peer *server, int tries);
int rs_server_set_secret(struct rs_peer *server, const char *secret);

int rs_packet_create_acc_request(struct rs_connection *conn, struct rs_packet **pkt, const char *user_name, const char *user_pw);
//int rs_packet_create_acc_accept(cstruct rs_connection *conn, struct rs_packet **pkt);
//int rs_packet_create_acc_reject(struct rs_connection *conn, struct rs_packet **pkt);
//int rs_packet_create_acc_challenge(struct rs_connection *conn, struct rs_packet **pkt);
void rs_packet_destroy(struct rs_packet *pkt);
void rs_packet_add_attr(struct rs_packet *pkt, struct rs_attr *attr);
//int rs_packet_add_new_attr(struct rs_packet *pkt, const char *attr_name, const char *attr_val);

int rs_attr_create(struct rs_connection *conn, struct rs_attr **attr, const char *type, const char *val);
void rs_attr_destroy(struct rs_attr *attr);

int rs_packet_send(struct rs_connection *conn, const struct rs_packet *pkt, void *user_data);
int rs_packet_recv(struct rs_connection *conn, struct rs_packet **pkt);

int rs_ctx_err_push(struct rs_handle *ctx, int code, const char *fmt, ...);
int rs_ctx_err_push_fl(struct rs_handle *ctx, int code, const char *file, int line, const char *fmt, ...);
struct rs_error *rs_ctx_err_pop (struct rs_handle *ctx);
int rs_conn_err_push(struct rs_connection *conn, int code, const char *fmt, ...);
int rs_conn_err_push_fl(struct rs_connection *conn, int code, const char *file, int line, const char *fmt, ...);
struct rs_error *rs_conn_err_pop (struct rs_connection *conn);
void rs_err_free(struct rs_error *err);
char *rs_err_msg(struct rs_error *err, int dofree_flag);
int rs_err_code(struct rs_error *err, int dofree_flag);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
