/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

int conn_user_dispatch_p (const struct rs_connection *conn);
int conn_close (struct rs_connection **connp);
int conn_activate_timeout (struct rs_connection *conn);
