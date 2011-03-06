/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <event2/event.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "debug.h"
#include "event.h"
#include "compat.h"
#include "udp.h"

/* Callback for conn->wev and conn->rev.  FIXME: Rename.  */
static void
_evcb (evutil_socket_t fd, short what, void *user_data)
{
  //rs_debug (("%s: fd=%d what=0x%x\n", __func__, fd, what));
  if (what & EV_TIMEOUT)
    {
      struct rs_connection *conn = (struct rs_connection *) user_data;
      assert (conn);
      conn->is_connecting = 0;
      rs_debug (("%s: UDP timeout NYI", __func__));
    }
  else if (what & EV_READ)
    {
      struct rs_connection *conn = (struct rs_connection *) user_data;
      assert (conn);
      /* read a single UDP packet and stick it in a new struct
	 rs_packet */

      rs_debug (("%s: UDP read NYI", __func__));
    }
  else if (what & EV_WRITE)
    {
      struct rs_packet *pkt = (struct rs_packet *) user_data;
      assert (pkt);
      /* Socket ready for writing, possibly as a result of a
	 successful connect.  */
      if (!pkt->conn->is_connected)
	event_on_connect (pkt->conn, pkt);
      if (pkt->conn->out_queue)
	{
	  /* Send one packet, the first.  */
	  ssize_t r = 0;
	  struct rs_packet *p = pkt->conn->out_queue;

	  assert (p->rpkt);
	  assert (p->rpkt->data);
	  r = compat_send (fd, p->rpkt->data, p->rpkt->data_len, 0);
	  if (r == -1)
	    {
	      int sockerr = evutil_socket_geterror (p->conn->fd);
	      if (sockerr != EAGAIN)
		rs_err_conn_push_fl (p->conn, RSE_SOCKERR, __FILE__, __LINE__,
				     "%d: send: %d (%s)", fd, sockerr,
				     evutil_socket_error_to_string (sockerr));
	      return;		/* Don't unlink packet. */
	    }
	  pkt->conn->out_queue = p->next;
	}
    }
}

int
udp_init (struct rs_connection *conn, struct rs_packet *pkt)
{
  assert (!conn->bev);

  conn->rev = event_new (conn->evb, conn->fd, EV_READ|EV_PERSIST, _evcb, conn);
  conn->wev = event_new (conn->evb, conn->fd, EV_WRITE|EV_PERSIST, _evcb, pkt);
  if (!conn->rev || !conn->wev)
    {
      if (conn->rev)
	event_free (conn->rev);
      /* ENOMEM _or_ EINVAL but EINVAL only if we use EV_SIGNAL, at
	 least for now (libevent-2.0.5).  */
      return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
    }
  return RSE_OK;
}
