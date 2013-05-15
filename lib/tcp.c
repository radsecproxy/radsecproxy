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
#include "packet.h"
#include "conn.h"
#include "debug.h"
#include "event.h"

#if defined (DEBUG)
#include <event2/buffer.h>
#endif

/** Read one RADIUS packet header. Return !0 on error. */
static int
_read_header (struct rs_packet *pkt)
{
  size_t n = 0;

  n = bufferevent_read (pkt->conn->bev, pkt->hdr, RS_HEADER_LEN);
  if (n == RS_HEADER_LEN)
    {
      pkt->flags |= RS_PACKET_HEADER_READ;
      pkt->rpkt->length = (pkt->hdr[2] << 8) + pkt->hdr[3];
      if (pkt->rpkt->length < 20 || pkt->rpkt->length > RS_MAX_PACKET_LEN)
	{
          rs_debug (("%s: invalid packet length: %d\n",
                     __func__, pkt->rpkt->length));
          rs_conn_disconnect (pkt->conn);
	  return rs_err_conn_push (pkt->conn, RSE_INVALID_PKT,
				   "invalid packet length: %d",
				   pkt->rpkt->length);
	}
      memcpy (pkt->rpkt->data, pkt->hdr, RS_HEADER_LEN);
      bufferevent_setwatermark (pkt->conn->bev, EV_READ,
				pkt->rpkt->length - RS_HEADER_LEN, 0);
      rs_debug (("%s: packet header read, total pkt len=%d\n",
		 __func__, pkt->rpkt->length));
    }
  else if (n < 0)
    {
      rs_debug (("%s: buffer frozen while reading header\n", __func__));
    }
  else	    /* Error: libevent gave us less than the low watermark. */
    {
      rs_debug (("%s: got: %d octets reading header\n", __func__, n));
      rs_conn_disconnect (pkt->conn);
      return rs_err_conn_push_fl (pkt->conn, RSE_INTERNAL, __FILE__, __LINE__,
				  "got %d octets reading header", n);
    }

  return 0;
}

/** Read a message, check that it's valid RADIUS and hand it off to
    registered user callback.

    The packet is read from the bufferevent associated with \a pkt and
    the data is stored in \a pkt->rpkt.

    Return 0 on success and !0 on failure. */
static int
_read_packet (struct rs_packet *pkt)
{
  size_t n = 0;
  int err;

  rs_debug (("%s: trying to read %d octets of packet data\n", __func__,
	     pkt->rpkt->length - RS_HEADER_LEN));

  n = bufferevent_read (pkt->conn->bev,
			pkt->rpkt->data + RS_HEADER_LEN,
			pkt->rpkt->length - RS_HEADER_LEN);

  rs_debug (("%s: read %ld octets of packet data\n", __func__, n));

  if (n == pkt->rpkt->length - RS_HEADER_LEN)
    {
      bufferevent_disable (pkt->conn->bev, EV_READ);
      rs_debug (("%s: complete packet read\n", __func__));
      pkt->flags &= ~RS_PACKET_HEADER_READ;
      memset (pkt->hdr, 0, sizeof(*pkt->hdr));

      /* Checks done by rad_packet_ok:
	 - lenghts (FIXME: checks really ok for tcp?)
	 - invalid code field
	 - attribute lengths >= 2
	 - attribute sizes adding up correctly  */
      err = nr_packet_ok (pkt->rpkt);
      if (err != RSE_OK)
	{
          rs_debug (("%s: %d: invalid packet\n", __func__, -err));
          rs_conn_disconnect (pkt->conn);
	  return rs_err_conn_push_fl (pkt->conn, -err, __FILE__, __LINE__,
				      "invalid packet");
	}

#if defined (DEBUG)
      /* Find out what happens if there's data left in the buffer.  */
      {
	size_t rest = 0;
	rest = evbuffer_get_length (bufferevent_get_input (pkt->conn->bev));
	if (rest)
	  rs_debug (("%s: returning with %d octets left in buffer\n", __func__,
		     rest));
      }
#endif

      /* Hand over message to user.  This changes ownership of pkt.
	 Don't touch it afterwards -- it might have been freed.  */
      if (pkt->conn->callbacks.received_cb)
	pkt->conn->callbacks.received_cb (pkt, pkt->conn->user_data);
    }
  else if (n < 0)		/* Buffer frozen.  */
    rs_debug (("%s: buffer frozen when reading packet\n", __func__));
  else				/* Short packet.  */
    rs_debug (("%s: waiting for another %d octets\n", __func__,
	       pkt->rpkt->length - RS_HEADER_LEN - n));

  return 0;
}

/* The read callback for TCP.

   Read exactly one RADIUS message from BEV and store it in struct
   rs_packet passed in USER_DATA.

   Inform upper layer about successful reception of received RADIUS
   message by invoking conn->callbacks.recevied_cb(), if !NULL.  */
void
tcp_read_cb (struct bufferevent *bev, void *user_data)
{
  struct rs_packet *pkt = (struct rs_packet *) user_data;

  assert (pkt);
  assert (pkt->conn);
  assert (pkt->rpkt);

  pkt->rpkt->sockfd = pkt->conn->fd;
  pkt->rpkt->vps = NULL;        /* FIXME: can this be done when initializing pkt? */

  /* Read a message header if not already read, return if that
     fails. Read a message and have it dispatched to the user
     registered callback.

     Room for improvement: Peek inside buffer (evbuffer_copyout()) to
     avoid the extra copying. */
  if ((pkt->flags & RS_PACKET_HEADER_READ) == 0)
    if (_read_header (pkt))
      return;			/* Error.  */
  _read_packet (pkt);
}

void
tcp_event_cb (struct bufferevent *bev, short events, void *user_data)
{
  struct rs_packet *pkt = (struct rs_packet *) user_data;
  struct rs_connection *conn = NULL;
  int sockerr = 0;
#if defined (RS_ENABLE_TLS)
  unsigned long tlserr = 0;
#endif
#if defined (DEBUG)
  struct rs_peer *p = NULL;
#endif

  assert (pkt);
  assert (pkt->conn);
  conn = pkt->conn;
#if defined (DEBUG)
  assert (pkt->conn->active_peer);
  p = conn->active_peer;
#endif

  conn->is_connecting = 0;
  if (events & BEV_EVENT_CONNECTED)
    {
      if (conn->tev)
	evtimer_del (conn->tev); /* Cancel connect timer.  */
      if (event_on_connect (conn, pkt))
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
	  rs_debug (("%s: %d: %d (%s)\n", __func__, conn->fd, sockerr,
		     evutil_socket_error_to_string (sockerr)));
	  rs_err_conn_push_fl (conn, RSE_SOCKERR, __FILE__, __LINE__,
			       "%d: %d (%s)", conn->fd, sockerr,
			       evutil_socket_error_to_string (sockerr));
	}
#if defined (RS_ENABLE_TLS)
      if (conn->tls_ssl)	/* FIXME: correct check?  */
	{
	  for (tlserr = bufferevent_get_openssl_error (conn->bev);
	       tlserr;
	       tlserr = bufferevent_get_openssl_error (conn->bev))
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
  struct rs_packet *pkt = (struct rs_packet *) ctx;

  assert (pkt);
  assert (pkt->conn);

  if (pkt->conn->callbacks.sent_cb)
    pkt->conn->callbacks.sent_cb (pkt->conn->user_data);
}

int
tcp_init_connect_timer (struct rs_connection *conn)
{
  assert (conn);

  if (conn->tev)
    event_free (conn->tev);
  conn->tev = evtimer_new (conn->evb, event_conn_timeout_cb, conn);
  if (!conn->tev)
    return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				"evtimer_new");

  return RSE_OK;
}
