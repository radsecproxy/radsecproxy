/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <event2/event.h>
#include <radius/client.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "debug.h"
#include "event.h"
#include "compat.h"
#include "udp.h"

/* Send one packet, the first in queue.  */
static int
_send (struct rs_connection *conn, int fd)
{
  ssize_t r = 0;
  struct rs_packet *pkt = conn->out_queue;

  assert (pkt->rpkt);
  assert (pkt->rpkt->data);

  /* Send.  */
  r = compat_send (fd, pkt->rpkt->data, pkt->rpkt->length, 0);
  if (r == -1)
    {
      int sockerr = evutil_socket_geterror (pkt->conn->fd);
      if (sockerr != EAGAIN)
	return rs_err_conn_push_fl (pkt->conn, RSE_SOCKERR, __FILE__, __LINE__,
				    "%d: send: %d (%s)", fd, sockerr,
				    evutil_socket_error_to_string (sockerr));
    }

  assert (r == pkt->rpkt->length);
  /* Unlink the packet.  */
  conn->out_queue = pkt->next;

  /* If there are more packets in queue, add the write event again.  */
  if (pkt->conn->out_queue)
    {
      r = event_add (pkt->conn->wev, NULL);
      if (r < 0)
	return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				    "event_add: %s", evutil_gai_strerror (r));
      rs_debug (("%s: re-adding the write event\n", __func__));
    }

  return RSE_OK;
}

/* Callback for conn->wev and conn->rev.  FIXME: Rename.

   USER_DATA contains connection for EV_READ and a packet for
   EV_WRITE.  This is because we don't have a connect/establish entry
   point at the user level -- send implies connect so when we're
   connected we need the packet to send.  */
static void
_evcb (evutil_socket_t fd, short what, void *user_data)
{
  int err;
  struct rs_packet *pkt = (struct rs_packet *) user_data;

  rs_debug (("%s: fd=%d what =", __func__, fd));
  if (what & EV_TIMEOUT) rs_debug ((" TIMEOUT -- shouldn't happen!"));
  if (what & EV_READ) rs_debug ((" READ"));
  if (what & EV_WRITE) rs_debug ((" WRITE"));
  rs_debug (("\n"));

  assert (pkt);
  assert (pkt->conn);
  if (what & EV_READ)
    {
      /* Read a single UDP packet and stick it in USER_DATA.  */
      /* TODO: Verify that unsolicited packets are dropped.  */
      ssize_t r = 0;

      assert (pkt->rpkt->data);

      r = compat_recv (fd, pkt->rpkt->data, RS_MAX_PACKET_LEN, MSG_TRUNC);
      if (r == -1)
	{
	  int sockerr = evutil_socket_geterror (pkt->conn->fd);
	  if (sockerr == EAGAIN)
	    {
	      /* FIXME: Really shouldn't happen since we've been told
		 that fd is readable!  */
	      rs_debug (("%s: EAGAIN reading UDP packet -- wot?\n"));
              goto err_out;
	    }

	  /* Hard error.  */
	  rs_err_conn_push_fl (pkt->conn, RSE_SOCKERR, __FILE__, __LINE__,
			       "%d: recv: %d (%s)", fd, sockerr,
			       evutil_socket_error_to_string (sockerr));
	  event_del (pkt->conn->tev);
          goto err_out;
	}
      event_del (pkt->conn->tev);
      if (r < 20 || r > RS_MAX_PACKET_LEN)	/* Short or long packet.  */
	{
	  rs_err_conn_push (pkt->conn, RSE_INVALID_PKT,
                            "invalid packet length: %d", r);
          goto err_out;
	}
      pkt->rpkt->length = (pkt->rpkt->data[2] << 8) + pkt->rpkt->data[3];
      err = nr_packet_ok (pkt->rpkt);
      if (err)
	{
	  rs_err_conn_push_fl (pkt->conn, -err, __FILE__, __LINE__,
			       "invalid packet");
          goto err_out;
	}
      /* Hand over message to user.  This changes ownership of pkt.
	 Don't touch it afterwards -- it might have been freed.  */
      if (pkt->conn->callbacks.received_cb)
	pkt->conn->callbacks.received_cb (pkt, pkt->conn->user_data);
      else
        rs_debug (("%s: no received-callback -- dropping packet\n", __func__));
    }
  else if (what & EV_WRITE)
    {
      if (!pkt->conn->is_connected)
	event_on_connect (pkt->conn, pkt);

      if (pkt->conn->out_queue)
	if (_send (pkt->conn, fd) == RSE_OK)
	  if (pkt->conn->callbacks.sent_cb)
	    pkt->conn->callbacks.sent_cb (pkt->conn->user_data);
    }
  return;

 err_out:
  rs_conn_disconnect (pkt->conn);
}

int
udp_init (struct rs_connection *conn, struct rs_packet *pkt)
{
  assert (!conn->bev);

  conn->rev = event_new (conn->evb, conn->fd, EV_READ|EV_PERSIST, _evcb, NULL);
  conn->wev = event_new (conn->evb, conn->fd, EV_WRITE, _evcb, NULL);
  if (!conn->rev || !conn->wev)
    {
      if (conn->rev)
	{
	  event_free (conn->rev);
	  conn->rev = NULL;
	}
      /* ENOMEM _or_ EINVAL but EINVAL only if we use EV_SIGNAL, at
	 least for now (libevent-2.0.5).  */
      return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
    }
  return RSE_OK;
}

int
udp_init_retransmit_timer (struct rs_connection *conn)
{
  assert (conn);

  if (conn->tev)
    event_free (conn->tev);
  conn->tev = evtimer_new (conn->evb, event_retransmit_timeout_cb, conn);
  if (!conn->tev)
    return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				"evtimer_new");

  return RSE_OK;
}
