/* Copyright 2010-2012 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined (__cplusplus)
extern "C" {
#endif

int tls_init (void);
int tls_init_conn (struct rs_connection *conn);
int tls_verify_cert (struct rs_connection *conn);

#define OPENSSL_VER(a,b,c,d,e) \
  (((a)<<28) |                 \
   ((b)<<20) |                 \
   ((c)<<12) |                 \
   ((d)<< 4) |                 \
    (e))
#define OPENSSL_V(a,b,c,d) \
  OPENSSL_VER((a),(b),(c),(d)-'a'+1,0xf)

#if defined (__cplusplus)
}
#endif
