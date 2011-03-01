/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
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

  conn->tls_ctx = ssl_ctx;
  conn->tls_ssl = ssl;
  rs_free (ctx, tlsconf);
  return RSE_OK;
}
