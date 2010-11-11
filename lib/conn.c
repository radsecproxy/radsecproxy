/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <event2/event.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

int
rs_conn_create (struct rs_context *ctx, struct rs_connection **conn,
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
rs_conn_set_type (struct rs_connection *conn, rs_conn_type_t type)
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
rs_conn_set_eventbase (struct rs_connection *conn, struct event_base *eb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int
rs_conn_set_callbacks (struct rs_connection *conn, struct rs_conn_callbacks *cb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int
rs_conn_select_server (struct rs_connection *conn, const char *name)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int
rs_conn_get_current_server (struct rs_connection *conn, const char *name,
			    size_t buflen)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int rs_conn_fd (struct rs_connection *conn)
{
  assert (conn);
  assert (conn->active_peer);
  return conn->active_peer->fd;
}
