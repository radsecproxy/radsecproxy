/* Copyright 2011-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#if defined (RS_ENABLE_TLS)
#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>
#endif
#include <radius/client.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "tcp.h"
#include "message.h"
#include "conn.h"
#include "debug.h"
#include "event.h"

#if defined (DEBUG)
#include <event2/buffer.h>
#endif

/** Read one RADIUS message header. Return !0 on error. */
static int
_read_header (struct rs_message *msg)
{
  size_t n = 0;

  n = bufferevent_read (TO_BASE_CONN(msg->conn)->bev, msg->hdr, RS_HEADER_LEN);
  if (n == RS_HEADER_LEN)
    {
      msg->flags |= RS_MESSAGE_HEADER_READ;
      msg->rpkt->length = (msg->hdr[2] << 8) + msg->hdr[3];
      if (msg->rpkt->length < 20 || msg->rpkt->length > RS_MAX_PACKET_LEN)
        {
          rs_debug (("%s: invalid packet length: %d\n", __func__,
                     msg->rpkt->length));
          rs_conn_disconnect (msg->conn);
          return  rs_err_conn_push (msg->conn, RSE_INVALID_MSG,
                                    "invalid message length: %d",
                                    msg->rpkt->length);
        }
      memcpy (msg->rpkt->data, msg->hdr, RS_HEADER_LEN);
      bufferevent_setwatermark (TO_BASE_CONN(msg->conn)->bev, EV_READ,
				msg->rpkt->length - RS_HEADER_LEN, 0);
      rs_debug (("%s: message header read, total msg len=%d\n",
		 __func__, msg->rpkt->length));
    }
  else if (n < 0)
    rs_debug (("%s: buffer frozen while reading header\n", __func__));
  else	    /* Error: libevent gave us less than the low watermark. */
    {
      rs_debug (("%s: got: %d octets reading header\n", __func__, n));
      rs_conn_disconnect (msg->conn);
      return rs_err_conn_push (msg->conn, RSE_INTERNAL,
                               "got %d octets reading header", n);
    }

  return RSE_OK;
}

/** Read a message, check that it's valid RADIUS and hand it off to
    registered user callback.

    The message is read from the bufferevent associated with \a msg and
    the data is stored in \a msg->rpkt.

    Return 0 on success and !0 on failure. */
static int
_read_message (struct rs_message *msg)
{
  size_t n = 0;
  int err;

  rs_debug (("%s: trying to read %d octets of message data\n", __func__,
	     msg->rpkt->length - RS_HEADER_LEN));

  n = bufferevent_read (msg->conn->base_.bev,
			msg->rpkt->data + RS_HEADER_LEN,
			msg->rpkt->length - RS_HEADER_LEN);

  rs_debug (("%s: read %ld octets of message data\n", __func__, n));

  if (n == msg->rpkt->length - RS_HEADER_LEN)
    {
      bufferevent_disable (msg->conn->base_.bev, EV_READ);
      rs_debug (("%s: complete message read\n", __func__));
      msg->flags &= ~RS_MESSAGE_HEADER_READ;
      memset (msg->hdr, 0, sizeof(*msg->hdr));

      /* Checks done by nr_packet_ok:
	 - lenghts (FIXME: checks really ok for tcp?)
	 - invalid code field
	 - attribute lengths >= 2
	 - attribute sizes adding up correctly  */
      err = nr_packet_ok (msg->rpkt);
      if (err)
	{
          rs_debug (("%s: %d: invalid packet\n", __func__, -err));
          rs_conn_disconnect (msg->conn);
          return rs_err_conn_push (msg->conn, -err, "invalid message");
        }

#if defined (DEBUG)
      /* Find out what happens if there's data left in the buffer.  */
      {
	size_t rest = 0;
	rest =
          evbuffer_get_length (bufferevent_get_input (msg->conn->base_.bev));
	if (rest)
	  rs_debug (("%s: returning with %d octets left in buffer\n", __func__,
		     rest));
      }
#endif

      /* Hand over message to user.  This changes ownership of msg.
	 Don't touch it afterwards -- it might have been freed.  */
      if (msg->conn->callbacks.received_cb)
	msg->conn->callbacks.received_cb (msg, msg->conn->base_.user_data);
    }
  else if (n < 0)		/* Buffer frozen.  */
    rs_debug (("%s: buffer frozen when reading message\n", __func__));
  else				/* Short message.  */
    rs_debug (("%s: waiting for another %d octets\n", __func__,
	       msg->rpkt->length - RS_HEADER_LEN - n));

  return 0;
}

/* The read callback for TCP.

   Read exactly one RADIUS message from \a bev and store it in the
   struct rs_message passed in \a user_data.

   Inform upper layer about successful reception of received RADIUS
   message by invoking conn->callbacks.recevied_cb(), if not NULL. */
void
tcp_read_cb (struct bufferevent *bev, void *user_data)
{
  struct rs_message *msg = (struct rs_message *) user_data;

  assert (msg);
  assert (msg->conn);
  assert (msg->rpkt);

  msg->rpkt->sockfd = msg->conn->base_.fd;
  msg->rpkt->vps = NULL; /* FIXME: can this be done when initializing msg? */

  /* Read a message header if not already read, return if that
     fails. Read a message and have it dispatched to the user
     registered callback.

     Room for improvement: Peek inside buffer (evbuffer_copyout()) to
     avoid the extra copying. */
  if ((msg->flags & RS_MESSAGE_HEADER_READ) == 0)
    if (_read_header (msg))
      return;                   /* Invalid header. */
  _read_message (msg);
}

void
tcp_event_cb (struct bufferevent *bev, short events, void *user_data)
{
  struct rs_message *msg = (struct rs_message *) user_data;
  struct rs_connection *conn = NULL;
  int sockerr = 0;
#if defined (RS_ENABLE_TLS)
  unsigned long tlserr = 0;
#endif
#if defined (DEBUG)
  struct rs_peer *p = NULL;
#endif

  assert (msg);
  assert (msg->conn);
  conn = msg->conn;
#if defined (DEBUG)
  assert (conn->active_peer);
  p = conn->active_peer;
#endif

  if (events & BEV_EVENT_CONNECTED)
    {
      int err = -1;

      if (conn_originating_p (conn)) /* We're a client. */
        {
          assert (conn->tev);
          if (conn->tev)
            evtimer_del (conn->tev); /* Cancel connect timer.  */
          err = event_on_connect_orig (conn, msg);
        }
      else                      /* We're a server. */
        {
          assert (conn->tev == NULL);
          err = event_on_connect_term (conn, msg);
        }
      if (err)
        {
          event_on_disconnect (conn);
          event_loopbreak (conn);
        }
    }
  else if (events & BEV_EVENT_EOF)
    {
      event_on_disconnect (conn);
    }
  else if (events & BEV_EVENT_TIMEOUT)
    {
      rs_debug (("%s: %p times out on %s\n", __func__, p,
		 (events & BEV_EVENT_READING) ? "read" : "write"));
      rs_err_conn_push_fl (conn, RSE_TIMEOUT_IO, __FILE__, __LINE__, NULL);
    }
  else if (events & BEV_EVENT_ERROR)
    {
      sockerr = evutil_socket_geterror (conn->active_peer->fd);
      if (sockerr == 0)	/* FIXME: True that errno == 0 means closed? */
	{
	  event_on_disconnect (conn);
	  rs_err_conn_push_fl (conn, RSE_DISCO, __FILE__, __LINE__, NULL);
	}
      else
	{
	  rs_debug (("%s: %d: %d (%s)\n", __func__, conn->base_.fd, sockerr,
		     evutil_socket_error_to_string (sockerr)));
	  rs_err_conn_push_fl (conn, RSE_SOCKERR, __FILE__, __LINE__,
			       "%d: %d (%s)", conn->base_.fd, sockerr,
			       evutil_socket_error_to_string (sockerr));
	}
#if defined (RS_ENABLE_TLS)
      if (conn->tls_ssl)	/* FIXME: correct check?  */
	{
	  for (tlserr = bufferevent_get_openssl_error (conn->base_.bev);
	       tlserr;
	       tlserr = bufferevent_get_openssl_error (conn->base_.bev))
	    {
	      rs_debug (("%s: openssl error: %s\n", __func__,
			 ERR_error_string (tlserr, NULL)));
	      rs_err_conn_push_fl (conn, RSE_SSLERR, __FILE__, __LINE__,
				   ERR_error_string (tlserr, NULL));
	    }
	}
#endif	/* RS_ENABLE_TLS */
      event_loopbreak (conn);
    }

#if defined (DEBUG)
  if (events & BEV_EVENT_ERROR && events != BEV_EVENT_ERROR)
    rs_debug (("%s: BEV_EVENT_ERROR and more: 0x%x\n", __func__, events));
#endif
}

void
tcp_write_cb (struct bufferevent *bev, void *ctx)
{
  struct rs_message *msg = (struct rs_message *) ctx;

  assert (msg);
  assert (msg->conn);

  if (msg->conn->callbacks.sent_cb)
    msg->conn->callbacks.sent_cb (msg->conn->base_.user_data);
}

int
tcp_init_connect_timer (struct rs_connection *conn)
{
  assert (conn);
  assert (conn->base_.ctx);

  if (conn->tev)
    event_free (conn->tev);
  conn->tev = evtimer_new (conn->base_.ctx->evb, event_conn_timeout_cb, conn);
  if (!conn->tev)
    return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				"evtimer_new");

  return RSE_OK;
}
