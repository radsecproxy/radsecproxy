/* Copyright 2011-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <string.h>
#include <errno.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#if defined (RS_ENABLE_TLS)
#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>
#endif
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "tcp.h"
#include "udp.h"
#if defined (RS_ENABLE_TLS)
#include "tls.h"
#endif
#include "err.h"
#include "radsec.h"
#include "event.h"
#include "packet.h"
#include "conn.h"
#include "debug.h"

#if defined (DEBUG)
extern int _event_debug_mode_on;
#endif

static void
_evlog_cb (int severity, const char *msg)
{
  const char *sevstr;
  switch (severity)
    {
    case _EVENT_LOG_DEBUG:
#if !defined (DEBUG_LEVENT)
      return;
#endif
      sevstr = "debug";
      break;
    case _EVENT_LOG_MSG:
      sevstr = "msg";
      break;
    case _EVENT_LOG_WARN:
      sevstr = "warn";
      break;
    case _EVENT_LOG_ERR:
      sevstr = "err";
      break;
    default:
      sevstr = "???";
      break;
    }
  fprintf (stderr, "libevent: [%s] %s\n", sevstr, msg); /* FIXME: stderr?  */
}

void
event_conn_timeout_cb (int fd, short event, void *data)
{
  struct rs_connection *conn = NULL;

  assert (data);
  conn = (struct rs_connection *) data;

  if (event & EV_TIMEOUT)
    {
      rs_debug (("%s: connection timeout on %p (fd %d) connecting to %p\n",
		 __func__, conn, conn->fd, conn->active_peer));
      conn->is_connecting = 0;
      rs_err_conn_push_fl (conn, RSE_TIMEOUT_CONN, __FILE__, __LINE__, NULL);
      event_loopbreak (conn);
    }
}

void
event_retransmit_timeout_cb (int fd, short event, void *data)
{
  struct rs_connection *conn = NULL;

  assert (data);
  conn = (struct rs_connection *) data;

  if (event & EV_TIMEOUT)
    {
      rs_debug (("%s: retransmission timeout on %p (fd %d) sending to %p\n",
		 __func__, conn, conn->fd, conn->active_peer));
      rs_err_conn_push_fl (conn, RSE_TIMEOUT_IO, __FILE__, __LINE__, NULL);
      event_loopbreak (conn);
    }
}

int
event_init_socket (struct rs_connection *conn, struct rs_peer *p)
{
  if (conn->fd != -1)
    return RSE_OK;

  if (p->addr_cache == NULL)
    {
      struct rs_error *err =
        rs_resolve (&p->addr_cache, p->realm->type, p->hostname, p->service);
      if (err != NULL)
        return err_conn_push_err (conn, err);
    }

  conn->fd = socket (p->addr_cache->ai_family, p->addr_cache->ai_socktype,
		     p->addr_cache->ai_protocol);
  if (conn->fd < 0)
    return rs_err_conn_push_fl (conn, RSE_SOCKERR, __FILE__, __LINE__,
				"socket: %d (%s)",
				errno, strerror (errno));
  if (evutil_make_socket_nonblocking (conn->fd) < 0)
    {
      evutil_closesocket (conn->fd);
      conn->fd = -1;
      return rs_err_conn_push_fl (conn, RSE_SOCKERR, __FILE__, __LINE__,
				  "evutil_make_socket_nonblocking: %d (%s)",
				  errno, strerror (errno));
    }
  return RSE_OK;
}

int
event_init_bufferevent (struct rs_connection *conn, struct rs_peer *peer)
{
  if (conn->bev)
    return RSE_OK;

  if (conn->realm->type == RS_CONN_TYPE_TCP)
    {
      conn->bev = bufferevent_socket_new (conn->evb, conn->fd, 0);
      if (!conn->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_socket_new");
    }
#if defined (RS_ENABLE_TLS)
  else if (conn->realm->type == RS_CONN_TYPE_TLS)
    {
      if (rs_tls_init (conn))
	return -1;
      /* Would be convenient to pass BEV_OPT_CLOSE_ON_FREE but things
	 seem to break when be_openssl_ctrl() (in libevent) calls
	 SSL_set_bio() after BIO_new_socket() with flag=1.  */
      conn->bev =
	bufferevent_openssl_socket_new (conn->evb, conn->fd, conn->tls_ssl,
					BUFFEREVENT_SSL_CONNECTING, 0);
      if (!conn->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_openssl_socket_new");
    }
#endif	/* RS_ENABLE_TLS */
  else
    {
      return rs_err_conn_push_fl (conn, RSE_INTERNAL, __FILE__, __LINE__,
				  "%s: unknown connection type: %d", __func__,
				  conn->realm->type);
    }

  return RSE_OK;
}

void
event_do_connect (struct rs_connection *conn)
{
  struct rs_peer *p;
  int err, sockerr;

  assert (conn);
  assert (conn->active_peer);
  p = conn->active_peer;

#if defined (DEBUG)
  {
    char host[80], serv[80];

    getnameinfo (p->addr_cache->ai_addr,
		 p->addr_cache->ai_addrlen,
		 host, sizeof(host), serv, sizeof(serv),
		 0 /* NI_NUMERICHOST|NI_NUMERICSERV*/);
    rs_debug (("%s: connecting to %s:%s\n", __func__, host, serv));
  }
#endif

  if (p->conn->bev)		/* TCP */
    {
      conn_activate_timeout (conn); /* Connect timeout.  */
      err = bufferevent_socket_connect (p->conn->bev, p->addr_cache->ai_addr,
					p->addr_cache->ai_addrlen);
      if (err < 0)
	rs_err_conn_push_fl (p->conn, RSE_EVENT, __FILE__, __LINE__,
			     "bufferevent_socket_connect: %s",
			     evutil_gai_strerror (err));
      else
	p->conn->is_connecting = 1;
    }
  else				/* UDP */
    {
      err = connect (p->conn->fd,
                     p->addr_cache->ai_addr,
                     p->addr_cache->ai_addrlen);
      if (err < 0)
	{
	  sockerr = evutil_socket_geterror (p->conn->fd);
	  rs_debug (("%s: %d: connect: %d (%s)\n", __func__, p->conn->fd,
		     sockerr, evutil_socket_error_to_string (sockerr)));
	  rs_err_conn_push_fl (p->conn, RSE_SOCKERR, __FILE__, __LINE__,
			       "%d: connect: %d (%s)", p->conn->fd, sockerr,
			       evutil_socket_error_to_string (sockerr));
	}
    }
}

int
event_loopbreak (struct rs_connection *conn)
{
  int err = event_base_loopbreak (conn->evb);
  if (err < 0)
    rs_err_conn_push (conn, RSE_EVENT, "event_base_loopbreak");
  return err;
}


void
event_on_disconnect (struct rs_connection *conn)
{
  conn->is_connecting = 0;
  conn->is_connected = 0;
  rs_debug (("%s: %p disconnected\n", __func__, conn->active_peer));
  if (conn->callbacks.disconnected_cb)
    conn->callbacks.disconnected_cb (conn->user_data);
}

/** Internal connect event returning 0 on success or -1 on error.  */
int
event_on_connect (struct rs_connection *conn, struct rs_packet *pkt)
{
  assert (!conn->is_connecting);

#if defined (RS_ENABLE_TLS)
  if (conn_type_tls(conn) && !conn_cred_psk(conn))
    if (tls_verify_cert (conn) != RSE_OK)
      {
        rs_debug (("%s: server cert verification failed\n", __func__));
        return -1;
      }
#endif	/* RS_ENABLE_TLS */

  conn->is_connected = 1;
  rs_debug (("%s: %p connected\n", __func__, conn->active_peer));

  if (conn->callbacks.connected_cb)
    conn->callbacks.connected_cb (conn->user_data);

  if (pkt)
    packet_do_send (pkt);

  return 0;
}

int
event_init_eventbase (struct rs_connection *conn)
{
  assert (conn);
  if (conn->evb)
    return RSE_OK;

#if defined (DEBUG)
  if (!_event_debug_mode_on)
    event_enable_debug_mode ();
#endif
  event_set_log_callback (_evlog_cb);
  conn->evb = event_base_new ();
  if (!conn->evb)
    return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				"event_base_new");

  return RSE_OK;
}
