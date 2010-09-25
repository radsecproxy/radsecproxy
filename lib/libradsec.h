/** @file libradsec.h
    @brief Header file for libradsec.  */
/* See the file COPYING for licensing information.  */

#include <unistd.h>

/* Data types.  */
struct rs_handle;		/* radsec-impl.h */
struct rs_alloc_scheme;		/* radsec-impl.h */
struct rs_connection;		/* radsec-impl.h */
struct rs_conn_callbacks;	/* radsec-impl.h */
struct rs_packet;		/* radsec-impl.h */
struct rs_conn;			/* radsec-impl.h */
struct event_base;		/* <event.h> */

/* Function prototypes.  */
int rs_context_create(struct rs_handle **ctx);
void rs_context_destroy(struct rs_handle *ctx);
int rs_context_set_alloc_scheme(struct rs_handle *ctx, struct rs_alloc_scheme *scheme);
int rs_context_config_read(struct rs_handle *ctx, const char *config_file);

int rs_conn_create(const struct rs_handle *ctx, struct rs_connection **conn);
int rs_conn_destroy(struct rs_connection  *conn);
int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb);
int rs_conn_set_callbacks(struct rs_connection *conn, struct rs_conn_callbacks *cb);
int rs_conn_set_server(struct rs_connection *conn, const char *name);
int rs_conn_get_server(const struct rs_connection *conn, const char *name, size_t buflen); /* NAME <-- most recent server we spoke to */

int rs_packet_send(const struct rs_conn *conn, const struct rs_packet *pkt, void *user_data);
int rs_packet_receive(const struct rs_conn *conn, struct rs_packet **pkt);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
