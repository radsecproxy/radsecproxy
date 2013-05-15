/* Copyright 2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

int conn_user_dispatch_p (const struct rs_connection *conn);
int conn_activate_timeout (struct rs_connection *conn);
int conn_cred_psk (const struct rs_connection *conn);
int conn_configure (struct rs_context *ctx,
                    struct rs_conn_base *connbase,
                    const char *config);
void conn_init (struct rs_context *ctx,
                struct rs_conn_base *connbase,
                enum rs_conn_subtype type);
int conn_type_tls_p (const struct rs_connection *conn);
int baseconn_type_datagram_p (const struct rs_conn_base *connbase);
int baseconn_type_stream_p (const struct rs_conn_base *connbase);
struct rs_peer *connbase_get_peers (const struct rs_conn_base *connbase);
int conn_add_read_event (struct rs_connection *conn, void *user_data);
int conn_originating_p (const struct rs_connection *conn);
int baseconn_close (struct rs_conn_base *connbase);
struct bufferevent *baseconn_get_bev (struct rs_conn_base *connbase);
