/* Copyright 2010-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>

#include <radius/client.h>
#include <event2/event.h>
#include <event2/util.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "err.h"
#include "debug.h"
#include "radsecproxy/debug.h"
#if defined (RS_ENABLE_TLS)
#include <regex.h>
#include "radsecproxy/list.h"
#include "radsecproxy/radsecproxy.h"
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

  debug_init ("libradsec");	/* radsecproxy compat, FIXME: remove */

  if (ctx != NULL)
    *ctx = h;

  return RSE_OK;
}

struct rs_error *
rs_resolve (struct evutil_addrinfo **addr,
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
	      if (p->addr_cache)
                {
                  evutil_freeaddrinfo (p->addr_cache);
                  p->addr_cache = NULL;
                }
	      p = p->next;
	      rs_free (ctx, tmp);
	    }
	  free (r->name);
          rs_free (ctx, r->transport_cred);
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

