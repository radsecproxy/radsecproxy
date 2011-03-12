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
#include "err.h"
#include "debug.h"
#include "rsp_debug.h"
#if defined (RS_ENABLE_TLS)
#include <regex.h>
#include "rsp_list.h"
#include "../radsecproxy.h"
#endif

/* Public functions.  */
int
rs_context_create (struct rs_context **ctx, const char *dict)
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

struct rs_error *	   /* FIXME: Return int as all the others?  */
rs_resolv (struct evutil_addrinfo **addr,
	   rs_conn_type_t type,
	   const char *hostname,
	   const char *service)
{
  int err;
  struct evutil_addrinfo hints, *res = NULL;

  memset (&hints, 0, sizeof(struct evutil_addrinfo));
  hints.ai_family = AF_INET;   /* IPv4 only.  TODO: Set AF_UNSPEC.  */
  hints.ai_flags = AI_ADDRCONFIG;
  switch (type)
    {
    case RS_CONN_TYPE_NONE:
      return err_create (RSE_INVALID_CONN, __FILE__, __LINE__, NULL, NULL);
    case RS_CONN_TYPE_TCP:
      /* Fall through.  */
    case RS_CONN_TYPE_TLS:
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      break;
    case RS_CONN_TYPE_UDP:
      /* Fall through.  */
    case RS_CONN_TYPE_DTLS:
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
      break;
    default:
      return err_create (RSE_INVALID_CONN, __FILE__, __LINE__, NULL, NULL);
    }
  err = evutil_getaddrinfo (hostname, service, &hints, &res);
  if (err)
    return err_create (RSE_BADADDR, __FILE__, __LINE__,
		       "%s:%s: bad host name or service name (%s)",
		       hostname, service, evutil_gai_strerror(err));
  *addr = res;			/* Simply use first result.  */
  return NULL;
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
	  if (p->addr)
	    evutil_freeaddrinfo (p->addr);
	  p = p->next;
	  rs_free (ctx, tmp);
	}
      rs_free (ctx, r->name);
      r = r->next;
      rs_free (ctx, tmp);
    }

  if (ctx->cfg)
    cfg_free (ctx->cfg);
  ctx->cfg = NULL;

  rs_free (ctx, ctx);
}

int
rs_context_set_alloc_scheme (struct rs_context *ctx,
			     struct rs_alloc_scheme *scheme)
{
  return rs_err_ctx_push_fl (ctx, RSE_NOSYS, __FILE__, __LINE__, NULL);
}

