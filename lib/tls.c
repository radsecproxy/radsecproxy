/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

#include <regex.h>
#include "rsp_list.h"
#include "../radsecproxy.h"

static struct tls *
_get_tlsconf (struct rs_connection *conn, const struct rs_realm *realm)
{
  struct tls *c = rs_malloc (conn->ctx, sizeof (struct tls));

  if (c)
    {
      memset (c, 0, sizeof (struct tls));
      /* TODO: Make sure old radsecproxy code doesn't free these all
	 of a sudden, or strdup them.  */
      c->name = realm->name;
      c->cacertfile = realm->cacertfile;
      c->cacertpath = NULL;	/* NYI */
      c->certfile = realm->certfile;
      c->certkeyfile = realm->certkeyfile;
      c->certkeypwd = NULL;	/* NYI */
      c->cacheexpiry = 0;	/* NYI */
      c->crlcheck = 0;		/* NYI */
      c->policyoids = (char **) NULL; /* NYI */
    }
    else
      rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);

  return c;
}

static unsigned int
psk_client_cb (SSL *ssl,
               const char *hint,
               char *identity,
               unsigned int max_identity_len,
               unsigned char *psk,
               unsigned int max_psk_len)
{
  struct rs_connection *conn = NULL;
  struct rs_credentials *cred = NULL;

  conn = SSL_get_ex_data (ssl, 0);
  assert (conn != NULL);
  cred = conn->active_peer->realm->transport_cred;
  assert (cred != NULL);
  /* NOTE: Ignoring identity hint from server.  */

  if (strlen (cred->identity) + 1 > max_identity_len)
    {
      rs_err_conn_push (conn, RSE_CRED, "PSK identity longer than max %d",
                        max_identity_len - 1);
      return 0;
    }
  strcpy (identity, cred->identity);

  switch (cred->secret_encoding)
    {
    case RS_KEY_ENCODING_UTF8:
      cred->secret_len = strlen (cred->secret);
      if (cred->secret_len > max_psk_len)
        {
          rs_err_conn_push (conn, RSE_CRED, "PSK secret longer than max %d",
                            max_psk_len);
          return 0;
        }
      memcpy (psk, cred->secret, cred->secret_len);
      break;
    case RS_KEY_ENCODING_ASCII_HEX:
      {
        BIGNUM *bn = NULL;

        if (BN_hex2bn (&bn, cred->secret) == 0)
          {
            rs_err_conn_push (conn, RSE_CRED, "Unable to convert pskhexstr");
            if (bn != NULL)
              BN_clear_free (bn);
            return 0;
          }
        if ((unsigned int) BN_num_bytes (bn) > max_psk_len)
          {
            rs_err_conn_push (conn, RSE_CRED, "PSK secret longer than max %d",
                             max_psk_len);
            BN_clear_free (bn);
            return 0;
          }
        cred->secret_len = BN_bn2bin (bn, psk);
        BN_clear_free (bn);
      }
      break;
    default:
      assert (!"unknown psk encoding");
    }

  return cred->secret_len;
}

int
rs_tls_init (struct rs_connection *conn)
{
  struct rs_context *ctx = NULL;
  struct tls *tlsconf = NULL;
  SSL_CTX *ssl_ctx = NULL;
  SSL *ssl = NULL;
  unsigned long sslerr = 0;

  assert (conn->ctx);
  ctx = conn->ctx;

  tlsconf = _get_tlsconf (conn, conn->active_peer->realm);
  if (!tlsconf)
    return -1;
  ssl_ctx = tlsgetctx (RADPROT_TLS, tlsconf);
  if (!ssl_ctx)
    {
      for (sslerr = ERR_get_error (); sslerr; sslerr = ERR_get_error ())
	 rs_err_conn_push_fl (conn, RSE_SSLERR, __FILE__, __LINE__,
			      ERR_error_string (sslerr, NULL));
      return -1;
    }
  ssl = SSL_new (ssl_ctx);
  if (!ssl)
    {
      for (sslerr = ERR_get_error (); sslerr; sslerr = ERR_get_error ())
	rs_err_conn_push_fl (conn, RSE_SSLERR, __FILE__, __LINE__,
			     ERR_error_string (sslerr, NULL));
      return -1;
    }

  if (conn->active_peer->realm->transport_cred != NULL)
    {
      SSL_set_psk_client_callback (ssl, psk_client_cb);
      SSL_set_ex_data (ssl, 0, conn);
    }
  conn->tls_ctx = ssl_ctx;
  conn->tls_ssl = ssl;
  rs_free (ctx, tlsconf);
  return RSE_OK;
}
