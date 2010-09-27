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
    RSE_SOME_ERROR = 21
};

enum rs_conn_type {
    RS_CONN_TYPE_UDP = 0,
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
struct event_base;		/* <event.h> */

/* Function prototypes.  */
int rs_context_create(struct rs_handle **ctx, const char *dict);
void rs_context_destroy(struct rs_handle *ctx);
int rs_context_set_alloc_scheme(struct rs_handle *ctx, struct rs_alloc_scheme *scheme);
int rs_context_config_read(struct rs_handle *ctx, const char *config_file);

int rs_conn_create(const struct rs_handle *ctx, struct rs_connection **conn);
int rs_conn_add_server(struct rs_connection  *conn, rs_conn_type_t type, const char *host, int port, int timeout, int tries, const char *secret);
int rs_conn_add_listener(struct rs_connection  *conn, rs_conn_type_t type, const char *host, int port, const char *secret);
int rs_conn_destroy(struct rs_connection  *conn);
int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb);
int rs_conn_set_callbacks(struct rs_connection *conn, struct rs_conn_callbacks *cb);
int rs_conn_set_server(struct rs_connection *conn, const char *name);
int rs_conn_get_server(const struct rs_connection *conn, const char *name, size_t buflen); /* NAME <-- most recent server we spoke to */

int rs_packet_create_acc_request(struct rs_connection *conn, struct rs_packet **pkt, const char *user_name, const char *user_pw);
//int rs_packet_create_acc_accept(cstruct rs_connection *conn, struct rs_packet **pkt);
//int rs_packet_create_acc_reject(struct rs_connection *conn, struct rs_packet **pkt);
//int rs_packet_create_acc_challenge(struct rs_connection *conn, struct rs_packet **pkt);
void rs_packet_destroy(struct rs_packet *pkt);
int rs_packet_add_attr(struct rs_packet *pkt, const struct rs_attr *attr);
//int rs_packet_add_new_attr(struct rs_packet *pkt, const char *attr_name, const char *attr_val);

int rs_attr_create(struct rs_connection *conn, struct rs_attr **attr, const char *type, const char *val);
void rs_attr_destroy(struct rs_attr *attr);

int rs_packet_send(struct rs_conn *conn, const struct rs_packet *pkt, void *user_data);
int rs_packet_receive(struct rs_conn *conn, struct rs_packet **pkt);


int rs_ctx_err_push (struct rs_handle *ctx, int code, const char *msg);
int rs_conn_err_push (struct rs_connection *conn, int code, const char *msg);
struct rs_error *rs_ctx_err_pop (struct rs_handle *ctx);
struct rs_error *rs_conn_err_pop (struct rs_connection *conn);
void rs_err_free (struct rs_error *err);
char *rs_err_msg (struct rs_error *err);
int rs_err_code (struct rs_error *err);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */



/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
