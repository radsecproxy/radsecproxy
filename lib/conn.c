/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "debug.h"
#include "conn.h"
#include "event.h"
#include "packet.h"
#include "tcp.h"

int
conn_close (struct rs_connection **connp)
{
  int r = 0;
  assert (connp);
  assert (*connp);
  if ((*connp)->is_connected)
    r = rs_conn_disconnect (*connp);
  if (r == RSE_OK)
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
rs_conn_create (struct rs_context *ctx,
		struct rs_connection **conn,
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

int
rs_conn_add_listener (struct rs_connection *conn,
		      rs_conn_type_t type,
		      const char *hostname,
		      int port)
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

#if defined (RS_ENABLE_TLS)
  if (conn->tls_ssl) /* FIXME: Free SSL strucxt in rs_conn_disconnect?  */
    SSL_free (conn->tls_ssl);
  if (conn->tls_ctx)
    SSL_CTX_free (conn->tls_ctx);
#endif

  if (conn->tev)
    event_free (conn->tev);
  if (conn->bev)
    bufferevent_free (conn->bev);
  if (conn->rev)
    event_free (conn->rev);
  if (conn->wev)
    event_free (conn->wev);
  if (conn->evb)
    event_base_free (conn->evb);

  rs_free (conn->ctx, conn);

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
rs_conn_get_current_peer (struct rs_connection *conn,
			  const char *name,
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

  assert (conn->evb);
  assert (conn->fd >= 0);

  conn->callbacks.received_cb = _rcb;
  conn->user_data = pkt;
  pkt->flags &= ~rs_packet_received_flag;

  if (conn->bev)		/* TCP.  */
    {
      bufferevent_setwatermark (conn->bev, EV_READ, RS_HEADER_LEN, 0);
      bufferevent_setcb (conn->bev, tcp_read_cb, NULL, tcp_event_cb, pkt);
      bufferevent_enable (conn->bev, EV_READ);
    }
  else				/* UDP.  */
    {
      /* Put fresh packet in user_data for the callback and enable the
	 read event.  */
      event_assign (conn->rev, conn->evb, event_get_fd (conn->rev),
		    EV_READ, event_get_callback (conn->rev), pkt);
      err = event_add (conn->rev, NULL);
      if (err < 0)
	return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				    "event_add: %s",
				    evutil_gai_strerror (err));

      /* Activae retransmission timer.  */
      conn_activate_timeout (pkt->conn);
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

int
conn_activate_timeout (struct rs_connection *conn)
{
  assert (conn);
  assert (conn->tev);
  assert (conn->evb);
  if (conn->timeout.tv_sec || conn->timeout.tv_usec)
    {
      rs_debug (("%s: activating timer: %d.%d\n", __func__,
		 conn->timeout.tv_sec, conn->timeout.tv_usec));
      if (evtimer_add (conn->tev, &conn->timeout))
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "evtimer_add: %d", errno);
    }
  return RSE_OK;
}
