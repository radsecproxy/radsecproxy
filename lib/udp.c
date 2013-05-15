/* Copyright 2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

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
#include "conn.h"

/* Send one packet, the first in queue.  */
static int
_send (struct rs_connection *conn, int fd)
{
  ssize_t r = 0;
  struct rs_message *msg = conn->out_queue;

  assert (msg->rpkt);
  assert (msg->rpkt->data);

  /* Send.  */
  r = compat_send (fd, msg->rpkt->data, msg->rpkt->length, 0);
  if (r == -1)
    {
      int sockerr = evutil_socket_geterror (msg->conn->fd);
      if (sockerr != EAGAIN)
	return rs_err_conn_push_fl (msg->conn, RSE_SOCKERR, __FILE__, __LINE__,
				    "%d: send: %d (%s)", fd, sockerr,
				    evutil_socket_error_to_string (sockerr));
    }

  assert (r == msg->rpkt->length);
  /* Unlink the message.  */
  conn->out_queue = msg->next;

  /* If there are more messages in queue, add the write event again.  */
  if (msg->conn->out_queue)
    {
      r = event_add (msg->conn->base_.wev, NULL);
      if (r < 0)
	return rs_err_conn_push_fl (msg->conn, RSE_EVENT, __FILE__, __LINE__,
				    "event_add: %s", evutil_gai_strerror (r));
      rs_debug (("%s: re-adding the write event\n", __func__));
    }

  return RSE_OK;
}

/** Callback for conn->wev and conn->rev.  FIXME: Rename.

    \a user_data holds a message. */
static void
_evcb (evutil_socket_t fd, short what, void *user_data)
{
  int err;
  struct rs_message *msg = (struct rs_message *) user_data;
  assert (msg);
  assert (msg->conn);

  rs_debug (("%s: fd=%d what =", __func__, fd));
  if (what & EV_TIMEOUT) rs_debug ((" TIMEOUT"));
  if (what & EV_READ) rs_debug ((" READ"));
  if (what & EV_WRITE) rs_debug ((" WRITE"));
  rs_debug (("\n"));

  if (what & EV_READ)
    {
      /* Read a single UDP packet and stick it in the struct
         rs_message passed in user_data. */
      /* TODO: Verify that unsolicited packets are dropped.  */
      ssize_t r = 0;
      assert (msg->rpkt);
      assert (msg->rpkt->data);

      r = compat_recv (fd, msg->rpkt->data, RS_MAX_PACKET_LEN, MSG_TRUNC);
      if (r == -1)
	{
	  int sockerr = evutil_socket_geterror (msg->conn->fd);
	  if (sockerr == EAGAIN)
	    {
	      /* FIXME: Really shouldn't happen since we've been told
		 that fd is readable!  */
	      rs_debug (("%s: EAGAIN reading UDP packet -- wot?"));
	      return;
	    }

	  /* Hard error.  */
	  rs_err_conn_push (msg->conn, RSE_SOCKERR,
                            "%d: recv: %d (%s)", fd, sockerr,
                            evutil_socket_error_to_string (sockerr));
	  event_del (msg->conn->tev);
	  return;
	}
      event_del (msg->conn->tev);
      if (r < 20 || r > RS_MAX_PACKET_LEN)	/* Short or long packet.  */
	{
	  rs_err_conn_push (msg->conn, RSE_INVALID_MSG,
			    "invalid message length: %d",
			    msg->rpkt->length);
	  return;
	}
      msg->rpkt->length = (msg->rpkt->data[2] << 8) + msg->rpkt->data[3];
      err = nr_packet_ok (msg->rpkt);
      if (err)
	{
	  rs_err_conn_push_fl (msg->conn, err, __FILE__, __LINE__,
			       "invalid message");
	  return;
	}
      /* Hand over message to user.  This changes ownership of msg.
	 Don't touch it afterwards -- it might have been freed.  */
      if (msg->conn->callbacks.received_cb)
	msg->conn->callbacks.received_cb (msg, msg->conn->base_.user_data);
    }
  else if (what & EV_WRITE)
    {
      if (conn_originating_p (msg->conn))
        {
          /* We're a client. */
          if (msg->conn->state == RS_CONN_STATE_CONNECTING)
            event_on_connect_orig (msg->conn, msg);
        }
      else
        {
          /* We're a server. */
          rs_debug (("%s: write event on terminating conn %p\n",
                     __func__, msg->conn));
        }

      if (msg->conn->out_queue)
	if (_send (msg->conn, fd) == RSE_OK)
	  if (msg->conn->callbacks.sent_cb)
	    msg->conn->callbacks.sent_cb (msg->conn->base_.user_data);
    }

#if defined (DEBUG)
  if (what & EV_TIMEOUT)
    rs_debug (("%s: timeout on UDP event, shouldn't happen\n", __func__));
#endif
}

int
udp_init (struct rs_connection *conn, struct rs_message *msg)
{
  assert (!conn->base_.bev);

  /* FIXME: Explain why we set EV_PERSIST on the read event but not on
     the write event. */
  conn->base_.rev = event_new (conn->base_.ctx->evb, conn->base_.fd,
                               EV_READ|EV_PERSIST, _evcb, NULL);
  conn->base_.wev = event_new (conn->base_.ctx->evb, conn->base_.fd,
                               EV_WRITE, _evcb, NULL);
  if (!conn->base_.rev || !conn->base_.wev)
    {
      if (conn->base_.rev)
	{
	  event_free (conn->base_.rev);
	  conn->base_.rev = NULL;
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
  assert (conn->base_.ctx);
  assert (conn->base_.ctx->evb);

  if (conn->tev)
    event_free (conn->tev);
  conn->tev =
    evtimer_new (conn->base_.ctx->evb, event_retransmit_timeout_cb, conn);
  if (!conn->tev)
    return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				"evtimer_new");

  return RSE_OK;
}
