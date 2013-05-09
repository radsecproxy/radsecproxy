/* Copyright 2010-2012 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined (__cplusplus)
extern "C" {
#endif

int rs_tls_init (struct rs_connection *conn);
int tls_verify_cert (struct rs_connection *conn);

#if defined (__cplusplus)
}
#endif
