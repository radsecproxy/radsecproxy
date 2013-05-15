/* Copyright 2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

int conn_user_dispatch_p (const struct rs_connection *conn);
int conn_activate_timeout (struct rs_connection *conn);
int conn_type_tls (const struct rs_connection *conn);
int conn_cred_psk (const struct rs_connection *conn);
