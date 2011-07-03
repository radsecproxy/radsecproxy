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
rs_context_create (struct rs_context **ctx)
{
  struct rs_context *h;

  h = calloc (1, sizeof(*h));
  if (h == NULL)
    return RSE_NOMEM;

#if defined (RS_ENABLE_TLS)
  ssl_init ();
#endif
#if defined (DEBUG)
  fr_log_fp = stderr;
  fr_debug_flag = 1;
#endif
  debug_init ("libradsec");	/* radsecproxy compat, FIXME: remove */

  fr_randinit (&h->fr_randctx, 0);
  fr_rand_seed (NULL, 0);

  if (ctx != NULL)
    *ctx = h;

  return RSE_OK;
}

/** Initialize freeradius dictionary.  */
int
rs_context_init_freeradius_dict (struct rs_context *ctx, const char *dict)
{
  int r = RSE_OK;
  size_t dictlen;
  char *dir = NULL;
  char *fn = NULL;

  if (dict == NULL)
    if (ctx->config != NULL && ctx->config->dictionary)
      dict = ctx->config->dictionary;

  if (dict == NULL)
    dict = RS_FREERADIUS_DICT;

  dictlen = strlen (dict);
  dir = rs_calloc (ctx, 1, dictlen + 1);
  fn = rs_calloc (ctx, 1, dictlen + 1);
  if (dir == NULL || fn == NULL)
    {
      r = rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);
      goto out;
    }
  strncpy (dir, dict, dictlen);
  strncpy (fn, dict, dictlen);

  if (dict_init (dirname (dir), basename (fn)) < 0)
    {
      r = rs_err_ctx_push_fl (ctx, RSE_FR, __FILE__, __LINE__,
			      "failing dict_init(\"%s\")", dict);
      goto out;
    }

 out:
  if (dir)
    rs_free (ctx, dir);
  if (fn)
    rs_free (ctx, fn);
  return r;
}

struct rs_error *
rs_resolv (struct evutil_addrinfo **addr,
	   rs_conn_type_t type,
	   const char *hostname,
	   const char *service)
{
  int err;
  struct evutil_addrinfo hints, *res = NULL;

  memset (&hints, 0, sizeof(struct evutil_addrinfo));
  hints.ai_family = AF_UNSPEC;
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

  if (ctx->config)
    {
      for (r = ctx->config->realms; r; )
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
	  free (r->name);
	  r = r->next;
	  rs_free (ctx, tmp);
	}
    }

  if (ctx->config)
    {
      if (ctx->config->cfg)
	{
	  cfg_free (ctx->config->cfg);
	  ctx->config->cfg = NULL;
	}
      rs_free (ctx, ctx->config);
    }

  free (ctx);
}

int
rs_context_set_alloc_scheme (struct rs_context *ctx,
			     struct rs_alloc_scheme *scheme)
{
  return rs_err_ctx_push_fl (ctx, RSE_NOSYS, __FILE__, __LINE__, NULL);
}

