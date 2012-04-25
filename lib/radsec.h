/* Copyright 2012 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

struct rs_error *rs_resolve (struct evutil_addrinfo **addr,
                             rs_conn_type_t type,
                             const char *hostname,
                             const char *service);
