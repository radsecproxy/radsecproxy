/* See the file COPYING for licensing information.  */

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

int
rs_context_create(struct rs_context **ctx, const char *dict)
{
  struct rs_context *h;

  if (ctx)
    *ctx = NULL;
  h = (struct rs_context *) malloc (sizeof(struct rs_context));
  if (h)
    {
      char *buf1 = NULL, *buf2 = NULL;
      char *dir, *fn;

      buf1 = malloc (strlen (dict) + 1);
      buf2 = malloc (strlen (dict) + 1);
      if (!buf1 || !buf2)
	{
	  free (h);
	  if (buf1)
	    free (buf1);
	  if (buf2)
	    free (buf2);
	  return RSE_NOMEM;
	}
      strcpy (buf1, dict);
      dir = dirname (buf1);
      strcpy (buf2, dict);
      fn = basename (buf2);
      if (dict_init (dir, fn) < 0)
	{
	  free (h);
	  return RSE_SOME_ERROR;
	}
      free (buf1);
      free (buf2);
#if defined (DEBUG)
      fr_log_fp = stderr;
      fr_debug_flag = 1;
#endif

      memset (h, 0, sizeof(struct rs_context));
      fr_randinit (&h->fr_randctx, 0);
      fr_rand_seed (NULL, 0);

      if (ctx)
	*ctx = h;
    }
  return h ? RSE_OK : RSE_NOMEM;
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

int
rs_conn_create(struct rs_context *ctx, struct rs_connection **conn,
	       const char *config)
{
  struct rs_connection *c;

  c = (struct rs_connection *) malloc (sizeof(struct rs_connection));
  if (c)
    {
      memset (c, 0, sizeof(struct rs_connection));
      c->ctx = ctx;
      if (config)
	{
	  struct rs_realm *r = rs_conf_find_realm (ctx, config);
	  if (r)
	    {
	      struct rs_peer *p;

	      c->type = r->type;
	      c->peers = r->peers; /* FIXME: Copy instead?  */
	      for (p = c->peers; p; p = p->next)
		p->conn = c;
	    }
	}
    }
  if (conn)
    *conn = c;
  return c ? RSE_OK : rs_err_ctx_push (ctx, RSE_NOMEM, NULL);
}

void
rs_conn_set_type(struct rs_connection *conn, rs_conn_type_t type)
{
  conn->type = type;
}


struct rs_error *
_rs_resolv (struct evutil_addrinfo **addr, rs_conn_type_t type,
	    const char *hostname, const char *service)
{
  int err;
  struct evutil_addrinfo hints, *res = NULL;

  memset (&hints, 0, sizeof(struct evutil_addrinfo));
  hints.ai_family = AF_UNSPEC;	/* v4 or v6.  */
  hints.ai_flags = AI_ADDRCONFIG;
  switch (type)
    {
    case RS_CONN_TYPE_NONE:
      return _rs_err_create (RSE_INVALID_CONN, __FILE__, __LINE__, NULL, NULL);
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
    }
  err = evutil_getaddrinfo (hostname, service, &hints, &res);
  if (err)
    return _rs_err_create (RSE_BADADDR, __FILE__, __LINE__,
			   "%s:%s: bad host name or service name (%s)",
			   hostname, service, evutil_gai_strerror(err));
  *addr = res;			/* Simply use first result.  */
  return NULL;
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

int
rs_conn_add_listener (struct rs_connection *conn, rs_conn_type_t type,
		      const char *hostname, int port)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

void
rs_conn_destroy (struct rs_connection *conn)
{
  struct rs_peer *p;

#warning "TODO: Disconnect active_peer."

  for (p = conn->peers; p; p = p->next)
    {
      if (p->addr)
	evutil_freeaddrinfo (p->addr);
      if (p->secret)
	rs_free (conn->ctx, p->secret);
    }

  if (conn->evb)
    event_base_free (conn->evb);
}

int
rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int
rs_conn_set_callbacks(struct rs_connection *conn, struct rs_conn_callbacks *cb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int
rs_conn_select_server(struct rs_connection *conn, const char *name)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int
rs_conn_get_current_server(struct rs_connection *conn, const char *name,
			   size_t buflen)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int rs_conn_fd(struct rs_connection *conn)
{
  assert (conn);
  assert (conn->active_peer);
  return conn->active_peer->fd;
}

