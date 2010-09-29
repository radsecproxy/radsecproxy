#include <string.h>
#include <assert.h>
#include <freeradius/libradius.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include "libradsec.h"
#include "libradsec-impl.h"
#if defined DEBUG
#include "debug.h"
#endif

int
_packet_create (struct rs_connection *conn, struct rs_packet **pkt_out,
		int code)
{
  struct rs_packet *p;
  RADIUS_PACKET *rpkt;

  *pkt_out = NULL;

  rpkt = rad_alloc (1);
  if (!rpkt)
    return rs_conn_err_push (conn, RSE_NOMEM, __func__);
  rpkt->id = -1;
  rpkt->code = code;

  p = (struct rs_packet *) malloc (sizeof (struct rs_packet));
  if (!p)
    {
      rad_free (&rpkt);
      return rs_conn_err_push (conn, RSE_NOMEM, __func__);
    }
  memset (p, 0, sizeof (struct rs_packet));
  p->conn = conn;
  p->rpkt = rpkt;

  *pkt_out = p;
  return RSE_OK;
}

int
rs_packet_create_acc_request (struct rs_connection *conn,
			      struct rs_packet **pkt_out,
			      const char *user_name, const char *user_pw)
{
  struct rs_packet *pkt;
  struct rs_attr *attr;

  if (_packet_create (conn, pkt_out, PW_AUTHENTICATION_REQUEST))
    return -1;
  pkt = *pkt_out;

  if (rs_attr_create (conn, &attr, "User-Name", user_name))
    return -1;
  rs_packet_add_attr (pkt, attr);

  if (rs_attr_create (conn, &attr, "User-Password", user_pw))
    return -1;
  /* FIXME: need this too? rad_pwencode(user_pw, &pwlen, SECRET, reqauth) */
  rs_packet_add_attr (pkt, attr);

  return RSE_OK;
}

static void
_event_cb (struct bufferevent *bev, short events, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *) ctx;

  assert (pkt);
  assert (pkt->conn);
  if (events & BEV_EVENT_CONNECTED)
    {
#if defined (DEBUG)
      fprintf (stderr, "%s: connected\n", __func__);
#endif
      rad_encode (pkt->rpkt, NULL, pkt->conn->active_peer->secret);
#if defined (DEBUG)
      fprintf (stderr, "%s: about to send this to %s:\n", __func__, "<fixme>");
      rs_dump_packet (pkt);
#endif
      if (bufferevent_write(bev, pkt->rpkt->data, pkt->rpkt->data_len))
	rs_conn_err_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
			     "bufferevent_write");
      /* Packet will be freed in write callback.  */
    }
  else if (events & BEV_EVENT_ERROR)
    rs_conn_err_push_fl (pkt->conn, RSE_CONNERR, __FILE__, __LINE__, NULL);
}

void
rs_packet_destroy(struct rs_packet *pkt)
{
  rad_free (&pkt->rpkt);
  rs_free (pkt->conn->ctx, pkt);
}

static void
_write_cb (struct bufferevent *bev, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *) ctx;

  assert (pkt);
  assert (pkt->conn);
#if defined (DEBUG)
  fprintf (stderr, "%s: packet written, breaking event loop\n", __func__);
#endif
  if (event_base_loopbreak (pkt->conn->evb) < 0)
    abort ();			/* FIXME */
  rs_packet_destroy (pkt);
}

int
rs_packet_send (struct rs_connection *conn, struct rs_packet *pkt, void *data)
{
  struct bufferevent *bev;
  struct rs_peer *p;

  assert (pkt->rpkt);

  if (rs_conn_open (conn))
    return -1;
  p = conn->active_peer;
  assert (p);

  assert (conn->active_peer->s >= 0);
  bev = bufferevent_socket_new (conn->evb, conn->active_peer->s, 0);
  if (!bev)
    return rs_conn_err_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				"bufferevent_socket_new");
  if (bufferevent_socket_connect (bev, p->addr->ai_addr, p->addr->ai_addrlen) < 0)
    {
      bufferevent_free (bev);
      return rs_conn_err_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				  "bufferevent_socket_connect");
    }

  bufferevent_setcb (bev, NULL, _write_cb, _event_cb, pkt);
  event_base_dispatch (conn->evb);
#if defined (DEBUG)
  fprintf (stderr, "%s: event loop done\n", __func__);
  assert (event_base_got_break(conn->evb));
#endif

  return RSE_OK;
}

int rs_packet_receive(struct rs_connection *conn, struct rs_packet **pkt)
{
  return rs_conn_err_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

void
rs_packet_add_attr(struct rs_packet *pkt, struct rs_attr *attr)
{
  pairadd (&pkt->rpkt->vps, attr->vp);
  attr->pkt = pkt;
}
