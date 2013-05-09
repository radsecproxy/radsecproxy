/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

struct rs_error *err_create (unsigned int code,
			     const char *file,
			     int line,
			     const char *fmt,
			     ...);
int err_conn_push_err (struct rs_connection *conn, struct rs_error *err);
