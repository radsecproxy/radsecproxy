/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

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

/* Read one RADIUS packet header.  Return !0 on error.  A return value
   of 0 means that we need more data.  */
static int
_read_header (struct rs_packet *pkt)
{
  size_t n = 0;

  n = bufferevent_read (pkt->conn->bev, pkt->hdr, RS_HEADER_LEN);
  if (n == RS_HEADER_LEN)
    {
      pkt->flags |= rs_packet_hdr_read_flag;
      pkt->rpkt->data_len = (pkt->hdr[2] << 8) + pkt->hdr[3];
      if (pkt->rpkt->data_len < 20 || pkt->rpkt->data_len > 4096)
	{
	  conn_close (&pkt->conn);
	  return rs_err_conn_push (pkt->conn, RSE_INVALID_PKT,
				   "invalid packet length: %d",
				   pkt->rpkt->data_len);
	}
      pkt->rpkt->data = rs_malloc (pkt->conn->ctx, pkt->rpkt->data_len);
      if (!pkt->rpkt->data)
	{
	  conn_close (&pkt->conn);
	  return rs_err_conn_push_fl (pkt->conn, RSE_NOMEM, __FILE__, __LINE__,
				      NULL);
	}
      memcpy (pkt->rpkt->data, pkt->hdr, RS_HEADER_LEN);
      bufferevent_setwatermark (pkt->conn->bev, EV_READ,
				pkt->rpkt->data_len - RS_HEADER_LEN, 0);
      rs_debug (("%s: packet header read, total pkt len=%d\n",
		 __func__, pkt->rpkt->data_len));
    }
  else if (n < 0)
    {
      rs_debug (("%s: buffer frozen while reading header\n", __func__));
    }
  else	    /* Error: libevent gave us less than the low watermark. */
    {
      conn_close (&pkt->conn);
      return rs_err_conn_push_fl (pkt->conn, RSE_INTERNAL, __FILE__, __LINE__,
				  "got %d octets reading header", n);
    }

  return 0;
}

static int
_read_packet (struct rs_packet *pkt)
{
  size_t n = 0;

  rs_debug (("%s: trying to read %d octets of packet data\n", __func__,
	     pkt->rpkt->data_len - RS_HEADER_LEN));

  n = bufferevent_read (pkt->conn->bev,
			pkt->rpkt->data + RS_HEADER_LEN,
			pkt->rpkt->data_len - RS_HEADER_LEN);

  rs_debug (("%s: read %ld octets of packet data\n", __func__, n));

  if (n == pkt->rpkt->data_len - RS_HEADER_LEN)
    {
      bufferevent_disable (pkt->conn->bev, EV_READ);
      rs_debug (("%s: complete packet read\n", __func__));
      pkt->flags &= ~rs_packet_hdr_read_flag;
      memset (pkt->hdr, 0, sizeof(*pkt->hdr));

      /* Checks done by rad_packet_ok:
	 - lenghts (FIXME: checks really ok for tcp?)
	 - invalid code field
	 - attribute lengths >= 2
	 - attribute sizes adding up correctly  */
      if (!rad_packet_ok (pkt->rpkt, 0))
	{
	  conn_close (&pkt->conn);
	  return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
				      "invalid packet: %s", fr_strerror ());
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
	       pkt->rpkt->data_len - RS_HEADER_LEN - n));

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
  pkt->rpkt->vps = NULL;

  if ((pkt->flags & rs_packet_hdr_read_flag) == 0)
    if (_read_header (pkt))
      return;			/* Error.  */
  _read_packet (pkt);
}

void
tcp_event_cb (struct bufferevent *bev, short events, void *user_data)
{
  struct rs_packet *pkt = (struct rs_packet *) user_data;
  struct rs_connection *conn = NULL;
  struct rs_peer *p = NULL;
  int sockerr = 0;
#if defined (RS_ENABLE_TLS)
  unsigned long tlserr = 0;
#endif

  assert (pkt);
  assert (pkt->conn);
  assert (pkt->conn->active_peer);
  conn = pkt->conn;
  p = conn->active_peer;

  conn->is_connecting = 0;
  if (events & BEV_EVENT_CONNECTED)
    {
      if (conn->tev)
	evtimer_del (conn->tev); /* Cancel connect timer.  */
      event_on_connect (conn, pkt);
    }
  else if (events & BEV_EVENT_EOF)
    {
      event_on_disconnect (conn);
    }
  else if (events & BEV_EVENT_TIMEOUT)
    {
      rs_debug (("%s: %p times out on %s\n", __func__, p,
		 (events & BEV_EVENT_READING) ? "read" : "write"));
      rs_err_conn_push_fl (pkt->conn, RSE_TIMEOUT_IO, __FILE__, __LINE__, NULL);
    }
  else if (events & BEV_EVENT_ERROR)
    {
      sockerr = evutil_socket_geterror (conn->active_peer->fd);
      if (sockerr == 0)	/* FIXME: True that errno == 0 means closed? */
	{
	  event_on_disconnect (conn);
	  rs_err_conn_push_fl (pkt->conn, RSE_DISCO, __FILE__, __LINE__, NULL);
	}
      else
	{
	  rs_debug (("%s: %d: %d (%s)\n", __func__, conn->fd, sockerr,
		     evutil_socket_error_to_string (sockerr)));
	  rs_err_conn_push_fl (pkt->conn, RSE_SOCKERR, __FILE__, __LINE__,
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
	      rs_err_conn_push_fl (pkt->conn, RSE_SSLERR, __FILE__, __LINE__,
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
