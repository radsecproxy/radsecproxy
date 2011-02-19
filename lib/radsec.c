/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>

#include <freeradius/libradius.h>
#include <event2/event.h>
#include <event2/util.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#if defined (RS_ENABLE_TLS)
#include <regex.h>
#include "rsp_list.h"
#include "../radsecproxy.h"
#endif
#include "rsp_debug.h"

int
rs_context_create(struct rs_context **ctx, const char *dict)
{
  int err = RSE_OK;
  struct rs_context *h;
  char *buf1 = NULL, *buf2 = NULL;
  char *dir, *fn;

  assert (dict);

  if (ctx)
    *ctx = NULL;
  h = (struct rs_context *) malloc (sizeof(struct rs_context));
  if (!h)
    return RSE_NOMEM;

  /* Initialize freeradius dictionary.  */
  buf1 = malloc (strlen (dict) + 1);
  buf2 = malloc (strlen (dict) + 1);
  if (!buf1 || !buf2)
    {
      err = RSE_NOMEM;
      goto err_out;
    }
  strcpy (buf1, dict);
  dir = dirname (buf1);
  strcpy (buf2, dict);
  fn = basename (buf2);
  if (dict_init (dir, fn) < 0)
    {
      err = RSE_SOME_ERROR;
      goto err_out;
    }
  free (buf1);
  free (buf2);

#if defined (RS_ENABLE_TLS)
  ssl_init ();
#endif
#if defined (DEBUG)
  fr_log_fp = stderr;
  fr_debug_flag = 1;
#endif
  debug_init ("libradsec");	/* radsecproxy compat, FIXME: remove */

  memset (h, 0, sizeof(struct rs_context));
  h->realms = malloc (sizeof (struct rs_realm));
  if (!h->realms)
    {
      err = RSE_NOMEM;
      goto err_out;
    }
  memset (h->realms, 0, sizeof (struct rs_realm));
  h->realms->next = h->realms;
  fr_randinit (&h->fr_randctx, 0);
  fr_rand_seed (NULL, 0);

  if (ctx)
    *ctx = h;

  return RSE_OK;

 err_out:
  if (buf1)
    free (buf1);
  if (buf2)
    free (buf2);
  if (h)
    free (h);
  return err;
}

void rs_context_destroy(struct rs_context *ctx)
{
  free (ctx);
}

int rs_context_set_alloc_scheme(struct rs_context *ctx,
				struct rs_alloc_scheme *scheme)
{
  return rs_err_ctx_push_fl (ctx, RSE_NOSYS, __FILE__, __LINE__,
			     "%s: NYI", __func__);
}


struct rs_peer *
_rs_peer_create (struct rs_context *ctx, struct rs_peer **rootp)
{
  struct rs_peer *p;

  p = (struct rs_peer *) rs_malloc (ctx, sizeof(*p));
  if (p)
    {
      memset (p, 0, sizeof(struct rs_peer));
      p->fd = -1;
      if (*rootp)
	(*rootp)->next = p;
      else
	*rootp = p;
    }
  return p;
}

int
rs_server_create (struct rs_connection *conn, struct rs_peer **server)
{
  struct rs_peer *srv;

  srv = _rs_peer_create (conn->ctx, &conn->peers);
  if (srv)
    {
      srv->conn = conn;
      srv->timeout = 1;
      srv->tries = 3;
    }
  else
    return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
  if (*server)
    *server = srv;
  return RSE_OK;
}

int
rs_server_set_address (struct rs_peer *server, const char *hostname,
		       const char *service)
{
  struct rs_error *err;

  err = _rs_resolv (&server->addr, server->conn->type, hostname, service);
  if (err)
    return _rs_err_conn_push_err (server->conn, err);
  return RSE_OK;
}

void
rs_server_set_timeout (struct rs_peer *server, int timeout)
{
  server->timeout = timeout;
}
void
rs_server_set_tries (struct rs_peer *server, int tries)
{
  server->tries = tries;
}

int
rs_server_set_secret (struct rs_peer *server, const char *secret)
{
  if (server->secret)
    free (server->secret);
  server->secret = (char *) malloc (strlen(secret) + 1);
  if (!server->secret)
    return rs_err_conn_push (server->conn, RSE_NOMEM, NULL);
  strcpy (server->secret, secret);
  return RSE_OK;
}

