/* See the file COPYING for licensing information.  */

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

static int
_packet_create (struct rs_connection *conn, struct rs_packet **pkt_out)
{
  struct rs_packet *p;
  RADIUS_PACKET *rpkt;

  *pkt_out = NULL;

  rpkt = rad_alloc (1);
  if (!rpkt)
    return rs_conn_err_push (conn, RSE_NOMEM, __func__);
  rpkt->id = -1;

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

  if (_packet_create (conn, pkt_out))
    return -1;
  pkt = *pkt_out;
  pkt->rpkt->code = PW_AUTHENTICATION_REQUEST;

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
  struct rs_connection *conn;
  struct rs_peer *p;

  assert (pkt);
  assert (pkt->conn);
  assert (pkt->conn->active_peer);
  conn = pkt->conn;
  p = conn->active_peer;

  p->is_connecting = 0;
  if (events & BEV_EVENT_CONNECTED)
    {
      p->is_connected = 1;
#if defined (DEBUG)
      fprintf (stderr, "%s: connected\n", __func__);
#endif
      rad_encode (pkt->rpkt, NULL, pkt->conn->active_peer->secret);
      assert (pkt->rpkt);
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

static void
_read_cb (struct bufferevent *bev, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *) ctx;
  size_t n;

  assert (pkt);
  assert (pkt->conn);
  if (!pkt->hdr_read_flag)
    {
      n = bufferevent_read (pkt->conn->bev, pkt->hdr, RS_HEADER_LEN;
      if (n == RS_HEADER_LEN)
	{
	  uint16_t len = (pkt->hdr[2] << 8) + pkt->hdr[3];
	  uint8_t *buf = rs_malloc (pkt->conn->ctx, len);

	  pkt->hdr_read_flag = 1;
	  if (!buf)
	    {
	      rs_conn_err_push_fl (pkt->conn, RSE_NOMEM, __FILE__,
				   __LINE__, NULL);
	      abort ();	/* FIXME: recovering takes reading of packet */
	    }
	  pkt->rpkt->data = buf;
	  pkt->rpkt->data_len = len;
	  bufferevent_setwatermark (pkt->conn->bev, EV_READ,
				    len - RS_HEADER_LEN, 0);
#if defined (DEBUG)
	  fprintf (stderr, "%s: packet header read, pkt len=%d\n", __func__,
		   len);
#endif
	}
      else if (n < 0)
	return;	/* Buffer frozen, i suppose.  Let's hope it thaws.  */
      else
	{
	  assert (n < RS_HEADER_LEN);
	  return;		/* Need more to complete header.  */
	  }
    }

  printf ("%s: trying to read %d octets of packet data\n", __func__, pkt->rpkt->data_len - RS_HEADER_LEN;
  n = bufferevent_read (pkt->conn->bev, pkt->rpkt->data,
			pkt->rpkt->data_len - RS_HEADER_LEN);
  printf ("%s: read %d octets of packet data\n", __func__, n);
  if (n == pkt->rpkt->data_len - RS_HEADER_LEN)
    {
      bufferevent_disable (pkt->conn->bev, EV_READ);
      pkt->hdr_read_flag = 0;
      memset (pkt->hdr, 0, sizeof(*pkt->hdr));
#if defined (DEBUG)
      fprintf (stderr, "%s: complete packet read\n", __func__);
#endif
      if (event_base_loopbreak (pkt->conn->evb) < 0)
	abort ();		/* FIXME */
    }
}

static int
_init_evb (struct rs_connection *conn)
{
  if (!conn->evb)
    {
#if defined (DEBUG)
      event_enable_debug_mode ();
#endif
      conn->evb = event_base_new ();
      if (!conn->evb)
	return rs_conn_err_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "event_base_new");
    }
  return RSE_OK;
}

static int
_init_socket (struct rs_connection *conn, struct rs_peer *p)
{
  if (p->s < 0)
    {
      assert (p->addr);
      p->s = socket (p->addr->ai_family, p->addr->ai_socktype,
		     p->addr->ai_protocol);
      if (p->s < 0)
	return rs_conn_err_push_fl (conn, RSE_SOME_ERROR, __FILE__, __LINE__,
				    strerror (errno));
    }
  return RSE_OK;
}

static struct rs_peer *
_pick_peer (struct rs_connection *conn)
{
  if (!conn->active_peer)
    conn->active_peer = conn->peers;
  return conn->active_peer;
}

static int
_init_bev (struct rs_connection *conn, struct rs_peer *peer)
{
  if (!conn->bev)
    {
      conn->bev = bufferevent_socket_new (conn->evb, peer->s, 0);
      if (!conn->bev)
	return rs_conn_err_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_socket_new");
    }
  return RSE_OK;
}

static void
_do_connect (struct rs_peer *p)
{
  if (bufferevent_socket_connect (p->conn->bev, p->addr->ai_addr,
				  p->addr->ai_addrlen) < 0)
    rs_conn_err_push_fl (p->conn, RSE_EVENT, __FILE__, __LINE__,
			   "bufferevent_socket_connect");
  else
    p->is_connecting = 1;
}

static int
_conn_open(struct rs_connection *conn, struct rs_packet *pkt)
{
  struct rs_peer *p;

  if (_init_evb (conn))
    return -1;

  p = _pick_peer (conn);
  if (!p)
    return rs_conn_err_push_fl (conn, RSE_NOPEER, __FILE__, __LINE__, NULL);

  if (_init_socket (conn, p))
    return -1;

  if (_init_bev (conn, p))
    return -1;
  bufferevent_setcb (conn->bev, _read_cb, _write_cb, _event_cb, pkt);

  if (!p->is_connected)
    if (!p->is_connecting)
      _do_connect (p);

  return RSE_OK;
}

int
rs_packet_send (struct rs_connection *conn, struct rs_packet *pkt, void *data)
{
  assert (conn);
  assert (pkt->rpkt);

  if (_conn_open (conn, pkt))
    return -1;
  assert (conn->evb);
  assert (conn->bev);
  assert (conn->active_peer);
  assert (conn->active_peer->s >= 0);

  event_base_dispatch (conn->evb);

#if defined (DEBUG)
  fprintf (stderr, "%s: event loop done\n", __func__);
  assert (event_base_got_break(conn->evb));
#endif

  return RSE_OK;
}

int
rs_packet_receive(struct rs_connection *conn, struct rs_packet **pkt_out)
{
  struct rs_packet *pkt;

  assert (conn);

  if (_packet_create (conn, pkt_out))
    return -1;
  pkt = *pkt_out;
  pkt->conn = conn;

  if (_conn_open (conn, pkt))
    return -1;
  assert (conn->evb);
  assert (conn->bev);
  assert (conn->active_peer);
  assert (conn->active_peer->s >= 0);

  bufferevent_setwatermark (conn->bev, EV_READ, RS_HEADER_LEN, 0);
  bufferevent_enable (conn->bev, EV_READ);
  event_base_dispatch (conn->evb);
#if defined (DEBUG)
  fprintf (stderr, "%s: event loop done\n", __func__);
  assert (event_base_got_break(conn->evb));
#endif

#if defined (DEBUG)
  fprintf (stderr, "%s: got this:\n", __func__);
  rs_dump_packet (pkt);
#endif

  return RSE_OK;
}

void
rs_packet_add_attr(struct rs_packet *pkt, struct rs_attr *attr)
{
  pairadd (&pkt->rpkt->vps, attr->vp);
  attr->pkt = pkt;
}
