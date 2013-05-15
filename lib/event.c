/* Copyright 2011-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <string.h>
#include <errno.h>

#include <event2/event.h>
#include <event2/listener.h>
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
#include "message.h"
#include "conn.h"
#include "listener.h"
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
		 __func__, conn, conn->base_.fd, conn->active_peer));
      conn->state = RS_CONN_STATE_UNDEFINED;
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
		 __func__, conn, conn->base_.fd, conn->active_peer));
      rs_err_conn_push_fl (conn, RSE_TIMEOUT_IO, __FILE__, __LINE__, NULL);
      event_loopbreak (conn);
    }
}

/* FIXME: event_ is actually not such a great prefix given that we
   link with libevent which exports 113 symbols prefixed 'event_'. */
int
event_init_socket (struct rs_conn_base *connbase, struct rs_peer *p)
{
  if (connbase->fd != -1)
    return RSE_OK;

  assert (p);
  assert (p->realm);

  /* Resolve potential DNS name for peer. */
  if (p->addr_cache == NULL)
    {
      struct rs_error *err =
        rs_resolve (&p->addr_cache, p->realm->type, p->hostname, p->service);
      if (err != NULL)
        return err_connbase_push_err (connbase, err);
    }

  /* Create the socket and make it non-blocking. */
  connbase->fd = socket (p->addr_cache->ai_family,
                         p->addr_cache->ai_socktype,
                         p->addr_cache->ai_protocol);
  if (connbase->fd < 0)
    return rs_err_connbase_push_fl (connbase, RSE_SOCKERR, __FILE__, __LINE__,
                                    "socket: %d (%s)",
                                    errno, strerror (errno));
  if (evutil_make_socket_nonblocking (connbase->fd) < 0)
    {
      evutil_closesocket (connbase->fd);
      connbase->fd = -1;
      return rs_err_connbase_push_fl (connbase, RSE_SOCKERR, __FILE__, __LINE__,
                                      "evutil_make_socket_nonblocking: %d (%s)",
                                      errno, strerror (errno));
    }

  /* If we're inititalising the socket for a listener, bind to the
     peer address. */
  if (connbase->magic == RS_CONN_MAGIC_LISTENER)
    {
      assert (p->realm->type == connbase->transport);
      if (p->realm->type == RS_CONN_TYPE_TLS
          || p->realm->type == RS_CONN_TYPE_TCP)
        {
          struct rs_listener *listener = TO_LISTENER_CONN (connbase);
          listener->evlistener =
            evconnlistener_new_bind (listener->base_.ctx->evb,
                                     listener_accept_cb_,
                                     listener, LEV_OPT_REUSEABLE,
                                     LISTENER_BACKLOG,
                                     p->addr_cache->ai_addr,
                                     p->addr_cache->ai_addrlen);
          if (listener->evlistener == NULL)
            return rs_err_connbase_push (connbase, RSE_EVENT,
                                         "evconnlistener_new_bind: %d (%s)",
                                         errno, strerror (errno));

          evconnlistener_set_error_cb (listener->evlistener, listener_err_cb_);
        }
      else
        {
          return rs_err_connbase_push_fl (connbase, RSE_NOSYS,
                                          __FILE__, __LINE__, NULL);
        }
    }

  return RSE_OK;
}

int
event_init_bufferevent (struct rs_connection *conn)
{
  struct rs_conn_base *connbase = NULL;
  assert (conn);
  connbase = TO_BASE_CONN(conn);

  if (connbase->bev)
    return RSE_OK;

  if (connbase->transport == RS_CONN_TYPE_TCP)
    {
      connbase->bev = bufferevent_socket_new (connbase->ctx->evb,
                                              connbase->fd, 0);
      if (!connbase->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
                                    "bufferevent_socket_new");
    }
#if defined (RS_ENABLE_TLS)
  else if (connbase->transport == RS_CONN_TYPE_TLS)
    {
      enum bufferevent_ssl_state bev_ssl_state;

      if (rs_tls_init (conn))
	return -1;
      bev_ssl_state = conn_originating_p (conn)
        ? BUFFEREVENT_SSL_CONNECTING : BUFFEREVENT_SSL_ACCEPTING;

      /* It would be convenient to pass BEV_OPT_CLOSE_ON_FREE in last
	 argument (options) but things seem to break when
	 be_openssl_ctrl() (in libevent) calls SSL_set_bio() after
	 BIO_new_socket() with flag=1. */
      connbase->bev =
	bufferevent_openssl_socket_new (connbase->ctx->evb, connbase->fd,
                                        conn->tls_ssl, bev_ssl_state, 0);
      if (!connbase->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_openssl_socket_new");
    }
#endif	/* RS_ENABLE_TLS */
  else
    {
      return rs_err_conn_push_fl (conn, RSE_INTERNAL, __FILE__, __LINE__,
				  "%s: unknown connection type: %d", __func__,
				  connbase->transport);
    }

  return RSE_OK;
}

void
event_do_connect (struct rs_connection *conn)
{
  int err, sockerr;
  struct sockaddr *peer_addr;
  size_t peer_addrlen;

  assert (conn);
  assert (conn->active_peer);
  assert (conn->active_peer->addr_cache);
  peer_addr = conn->active_peer->addr_cache->ai_addr;
  peer_addrlen = conn->active_peer->addr_cache->ai_addrlen;

  /* We don't connect listeners. */
  assert (conn->base_.magic == RS_CONN_MAGIC_GENERIC);

#if defined (DEBUG)
  {
    char host[80], serv[80];

    getnameinfo (peer_addr, peer_addrlen,
		 host, sizeof(host),
                 serv, sizeof(serv),
		 0 /* NI_NUMERICHOST|NI_NUMERICSERV*/);
    rs_debug (("%s: connecting to %s:%s\n", __func__, host, serv));
  }
#endif

  if (conn->base_.bev)		/* TCP */
    {
      conn_activate_timeout (conn); /* Connect timeout.  */
      err = bufferevent_socket_connect (conn->base_.bev,
                                        peer_addr, peer_addrlen);
      if (err < 0)
	rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
                             "bufferevent_socket_connect: %s",
                             evutil_gai_strerror (err));
      else
	conn->state = RS_CONN_STATE_CONNECTING;
    }
  else				/* UDP */
    {
      err = connect (conn->base_.fd, peer_addr, peer_addrlen);
      if (err < 0)
	{
	  sockerr = evutil_socket_geterror (conn->base_.fd);
	  rs_debug (("%s: %d: connect: %d (%s)\n", __func__,
                     conn->base_.fd,
		     sockerr, evutil_socket_error_to_string (sockerr)));
	  rs_err_conn_push (conn, RSE_SOCKERR,
                            "%d: connect: %d (%s)", conn->base_.fd,
                            sockerr, evutil_socket_error_to_string (sockerr));
	}
      else
	conn->state = RS_CONN_STATE_CONNECTING;
    }
}

int
event_loopbreak (struct rs_connection *conn)
{
  int err = event_base_loopbreak (TO_BASE_CONN(conn)->ctx->evb);
  if (err < 0)
    rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
			 "event_base_loopbreak: %s",
			 evutil_gai_strerror (err)); /* FIXME: really gai_strerror? */
  return err;
}


void
event_on_disconnect (struct rs_connection *conn)
{
  conn->state = RS_CONN_STATE_UNDEFINED;
  rs_debug (("%s: %p disconnected\n", __func__, conn->active_peer));
  if (conn->callbacks.disconnected_cb)
    conn->callbacks.disconnected_cb (conn->base_.user_data);
}

/** Internal connect event for originating connections. Returns 0 on
    success and -1 on TLS certificate verification failure.  */
int
event_on_connect_orig (struct rs_connection *conn, struct rs_message *msg)
{
  assert (conn->state == RS_CONN_STATE_CONNECTING);
  assert (conn->active_peer);

#if defined (RS_ENABLE_TLS)
  if (conn_type_tls_p (conn) && !conn_cred_psk (conn))
    if (tls_verify_cert (conn) != RSE_OK)
      {
        rs_debug (("%s: server cert verification failed\n", __func__));
        return -1;
      }
#endif	/* RS_ENABLE_TLS */

  conn->state = RS_CONN_STATE_CONNECTED;
  rs_debug (("%s: %p connected\n", __func__, conn->active_peer));

  if (conn->callbacks.connected_cb)
    conn->callbacks.connected_cb (conn->base_.user_data);

  if (msg)
    message_do_send (msg);

  return 0;
}

/** FIXME: DOC */
int
event_on_connect_term (struct rs_connection *conn, struct rs_message *msg)
{
  /* TODO: verify client */
  conn->state = RS_CONN_STATE_CONNECTED;
  rs_debug (("%s: WARNING: not checking client cert!!!\n", __func__));
  if (conn->callbacks.connected_cb)
    conn->callbacks.connected_cb (conn->base_.user_data);
  return 0;
}

int
event_init_eventbase (struct rs_conn_base *connbase)
{
  assert (connbase);
  assert (connbase->ctx);
  if (connbase->ctx->evb)
    return RSE_OK;

#if defined (DEBUG)
  if (!_event_debug_mode_on)
    event_enable_debug_mode ();
#endif
  event_set_log_callback (_evlog_cb);
  connbase->ctx->evb = event_base_new ();
  if (!connbase->ctx->evb)
    return rs_err_connbase_push_fl (connbase, RSE_EVENT, __FILE__, __LINE__,
                                    "event_base_new");

  return RSE_OK;
}
