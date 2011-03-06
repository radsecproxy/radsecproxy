/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

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
#include "debug.h"
#include "rsp_list.h"
#include "../radsecproxy.h"
#endif
#include "rsp_debug.h"


/* Public functions.  */
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
      err = RSE_FR;
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

struct rs_peer *
_rs_peer_create (struct rs_context *ctx, struct rs_peer **rootp)
{
  struct rs_peer *p;

  p = (struct rs_peer *) rs_malloc (ctx, sizeof(*p));
  if (p)
    {
      memset (p, 0, sizeof(struct rs_peer));
      if (*rootp)
	{
	  p->next = (*rootp)->next;
	  (*rootp)->next = p;
	}
      else
	*rootp = p;
    }
  return p;
}

static void
_rs_peer_destroy (struct rs_peer *p)
{
  assert (p);
  assert (p->conn);
  assert (p->conn->ctx);
  /* NOTE: The peer object doesn't own its connection (conn).  */
  if (p->addr)
    {
      evutil_freeaddrinfo (p->addr);
      p->addr = NULL;
    }
  if (p->secret)
    rs_free (p->conn->ctx, p->secret);
  rs_free (p->conn->ctx, p);
}

void
rs_context_destroy (struct rs_context *ctx)
{
  struct rs_realm *r = NULL;
  struct rs_peer *p = NULL;

  for (r = ctx->realms; r; )
    {
      struct rs_realm *tmp = r;
      for (p = r->peers; p; )
	{
	  struct rs_peer *tmp = p;
	  p = p->next;
	  _rs_peer_destroy (tmp);
	}
      r = r->next;
      rs_free (ctx, tmp);
    }

  if (ctx->cfg)
    cfg_free (ctx->cfg);
  ctx->cfg = NULL;

  rs_free (ctx, ctx);
}

int rs_context_set_alloc_scheme(struct rs_context *ctx,
				struct rs_alloc_scheme *scheme)
{
  return rs_err_ctx_push_fl (ctx, RSE_NOSYS, __FILE__, __LINE__, NULL);
}
