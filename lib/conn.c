/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <assert.h>
#include <debug.h>
#include <event2/event.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

int
rs_conn_create (struct rs_context *ctx, struct rs_connection **conn,
		const char *config)
{
  struct rs_connection *c;

  c = (struct rs_connection *) malloc (sizeof(struct rs_connection));
  if (!c)
    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);

  memset (c, 0, sizeof(struct rs_connection));
  c->ctx = ctx;
  c->fd = -1;
  if (config)
    {
      struct rs_realm *r = rs_conf_find_realm (ctx, config);
      if (r)
	{
	  struct rs_peer *p;

	  c->realm = r;
	  c->peers = r->peers;	/* FIXME: Copy instead?  */
	  for (p = c->peers; p; p = p->next)
	    p->conn = c;
	  c->tryagain = r->retries;
	}
      else
	{
	  c->realm = rs_malloc (ctx, sizeof (struct rs_realm));
	  if (!c->realm)
	    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__,
				       NULL);
	  memset (c->realm, 0, sizeof (struct rs_realm));
	}
    }

  if (conn)
    *conn = c;
  return RSE_OK;
}

void
rs_conn_set_type (struct rs_connection *conn, rs_conn_type_t type)
{
  assert (conn);
  assert (conn->realm);
  conn->realm->type = type;
}


struct rs_error *	   /* FIXME: Return int as all the others?  */
_rs_resolv (struct evutil_addrinfo **addr, rs_conn_type_t type,
	    const char *hostname, const char *service)
{
  int err;
  struct evutil_addrinfo hints, *res = NULL;

  memset (&hints, 0, sizeof(struct evutil_addrinfo));
  hints.ai_family = AF_INET;   /* IPv4 only.  TODO: Set AF_UNSPEC.  */
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
    default:
      return _rs_err_create (RSE_INVALID_CONN, __FILE__, __LINE__, NULL, NULL);
    }
  err = evutil_getaddrinfo (hostname, service, &hints, &res);
  if (err)
    return _rs_err_create (RSE_BADADDR, __FILE__, __LINE__,
			   "%s:%s: bad host name or service name (%s)",
			   hostname, service, evutil_gai_strerror(err));
  *addr = res;			/* Simply use first result.  */
  return NULL;
}

int
rs_conn_add_listener (struct rs_connection *conn, rs_conn_type_t type,
		      const char *hostname, int port)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}


int
rs_conn_disconnect (struct rs_connection *conn)
{
  int err = 0;

  assert (conn);

  err = evutil_closesocket (conn->fd);
  conn->fd = -1;
  return err;
}

int
rs_conn_destroy (struct rs_connection *conn)
{
  int err = 0;

  assert (conn);

  if (conn->is_connected)
    {
      err = rs_conn_disconnect (conn);
      if (err)
	return err;
    }

  /* NOTE: conn->realm is owned by context.  */
  /* NOTE: conn->peers is owned by context.  */

  if (conn->tev)
    event_free (conn->tev);
  if (conn->evb)
    event_base_free (conn->evb);

  return 0;
}

int
rs_conn_set_eventbase (struct rs_connection *conn, struct event_base *eb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

void
rs_conn_set_callbacks (struct rs_connection *conn, struct rs_conn_callbacks *cb)
{
  assert (conn);
  conn->user_dispatch_flag = 1;
  memcpy (&conn->callbacks, cb, sizeof (conn->callbacks));
}

void
rs_conn_del_callbacks (struct rs_connection *conn)
{
  assert (conn);
  conn->user_dispatch_flag = 0;
  memset (&conn->callbacks, 0, sizeof (conn->callbacks));
}

struct rs_conn_callbacks *
rs_conn_get_callbacks(struct rs_connection *conn)
{
  assert (conn);
  return &conn->callbacks;
}

int
rs_conn_select_peer (struct rs_connection *conn, const char *name)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int
rs_conn_get_current_peer (struct rs_connection *conn, const char *name,
			  size_t buflen)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int rs_conn_fd (struct rs_connection *conn)
{
  assert (conn);
  assert (conn->active_peer);
  return conn->fd;
}
