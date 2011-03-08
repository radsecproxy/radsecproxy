/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <assert.h>
#include <debug.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "conn.h"
#include "event.h"
#include "packet.h"
#include "tcp.h"

int
conn_close (struct rs_connection **connp)
{
  int r;
  assert (connp);
  assert (*connp);
  r = rs_conn_destroy (*connp);
  if (!r)
    *connp = NULL;
  return r;
}

int
conn_user_dispatch_p (const struct rs_connection *conn)
{
  assert (conn);

  return (conn->callbacks.connected_cb ||
	  conn->callbacks.disconnected_cb ||
	  conn->callbacks.received_cb ||
	  conn->callbacks.sent_cb);
}

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
	  c->timeout.tv_sec = r->timeout;
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
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__, NULL);
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

  /* NOTE: conn->realm is owned by context.  */
  /* NOTE: conn->peers is owned by context.  */

  if (conn->is_connected)
    err = rs_conn_disconnect (conn);
  if (conn->tev)
    event_free (conn->tev);
  if (conn->bev)
    bufferevent_free (conn->bev);
  if (conn->evb)
    event_base_free (conn->evb);

  /* TODO: free tls_ctx  */
  /* TODO: free tls_ssl  */

  return err;
}

int
rs_conn_set_eventbase (struct rs_connection *conn, struct event_base *eb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__, NULL);
}

void
rs_conn_set_callbacks (struct rs_connection *conn, struct rs_conn_callbacks *cb)
{
  assert (conn);
  memcpy (&conn->callbacks, cb, sizeof (conn->callbacks));
}

void
rs_conn_del_callbacks (struct rs_connection *conn)
{
  assert (conn);
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
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__, NULL);
}

int
rs_conn_get_current_peer (struct rs_connection *conn, const char *name,
			  size_t buflen)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__, NULL);
}

int rs_conn_fd (struct rs_connection *conn)
{
  assert (conn);
  assert (conn->active_peer);
  return conn->fd;
}

static void
_rcb (struct rs_packet *packet, void *user_data)
{
  struct rs_packet *pkt = (struct rs_packet *) user_data;
  assert (pkt);
  assert (pkt->conn);

  pkt->flags |= rs_packet_received_flag;
  if (pkt->conn->bev)
    bufferevent_disable (pkt->conn->bev, EV_WRITE|EV_READ);
  else
    event_del (pkt->conn->rev);
}

/* Special function used in libradsec blocking dispatching mode,
   i.e. with socket set to block on read/write and with no libradsec
   callbacks registered.

   For any other use of libradsec, a the received_cb callback should
   be registered in the callbacks member of struct rs_connection.

   On successful reception of a RADIUS message it will be verified
   against REQ_MSG, if !NULL.

   If PKT_OUT is !NULL it will upon return point at a pointer to a
   struct rs_packet containing the message.

   If anything goes wrong or if the read times out (TODO: explain),
   PKT_OUT will not be changed and one or more errors are pushed on
   the connection (available through rs_err_conn_pop()).  */
int
rs_conn_receive_packet (struct rs_connection *conn,
		        struct rs_packet *req_msg,
		        struct rs_packet **pkt_out)
{
  int err = 0;
  struct rs_packet *pkt = NULL;

  assert (conn);
  assert (conn->realm);
  assert (!conn_user_dispatch_p (conn)); /* Dispatching mode only.  */

  if (rs_packet_create (conn, &pkt))
    return -1;
  pkt->conn = conn;

  assert (conn->evb);
  assert (conn->bev);
  assert (conn->active_peer);
  assert (conn->fd >= 0);

  conn->callbacks.received_cb = _rcb;
  conn->user_data = pkt;
  pkt->flags &= ~rs_packet_received_flag;

  if (conn->bev)
    {
      bufferevent_setwatermark (conn->bev, EV_READ, RS_HEADER_LEN, 0);
      bufferevent_setcb (conn->bev, tcp_read_cb, NULL, tcp_event_cb, pkt);
      bufferevent_enable (conn->bev, EV_READ);
    }
  else
    {
      err = event_add (conn->rev, NULL);
      if (err < 0)
	return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				    "event_add: %s",
				    evutil_gai_strerror (err));
    }


  rs_debug (("%s: entering event loop\n", __func__));
  err = event_base_dispatch (conn->evb);
  conn->callbacks.received_cb = NULL;
  if (err < 0)
    return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				"event_base_dispatch: %s",
				evutil_gai_strerror (err));
  rs_debug (("%s: event loop done\n", __func__));

  if ((pkt->flags & rs_packet_received_flag) == 0
      || (req_msg
	  && packet_verify_response (pkt->conn, pkt, req_msg) != RSE_OK))
    {
      assert (rs_err_conn_peek_code (pkt->conn));
      return rs_err_conn_peek_code (conn);
    }

  if (pkt_out)
    *pkt_out = pkt;
  return RSE_OK;
}

void
rs_conn_set_timeout(struct rs_connection *conn, struct timeval *tv)
{
  assert (conn);
  assert (tv);
  conn->timeout = *tv;
}
