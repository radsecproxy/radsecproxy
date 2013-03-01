/* Copyright 2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

struct rs_error *err_create (unsigned int code,
			     const char *file,
			     int line,
			     const char *fmt,
			     ...);
int err_connbase_push_err (struct rs_conn_base *, struct rs_error *);
int rs_err_connbase_push (struct rs_conn_base *, int, const char *, ...);
