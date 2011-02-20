/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <openssl/ssl.h>
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
  struct rs_context *ctx;
  struct tls *tlsconf;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  assert (conn->ctx);
  ctx = conn->ctx;

  tlsconf = _get_tlsconf (conn, conn->active_peer->realm);
  if (!tlsconf)
    return -1;
  ssl_ctx = tlsgetctx (RADPROT_TLS, tlsconf);
  if (!ssl_ctx)
    {
      /* TODO: check radsecproxy error  */
      return rs_err_conn_push_fl (conn, RSE_SOME_ERROR, __FILE__, __LINE__,
				  NULL);
    }

  ssl = SSL_new (ssl_ctx);
  if (!ssl)
    {
      /* TODO: check and report SSL error  */
      /* TODO: free ssl_ctx  */
      return rs_err_conn_push_fl (conn, RSE_SOME_ERROR, __FILE__, __LINE__,
				  NULL);
    }

  conn->tls_ctx = ssl_ctx;
  conn->tls_ssl = ssl;
  rs_free (ctx, tlsconf);
  return RSE_OK;
}
