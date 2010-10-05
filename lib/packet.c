/* See the file COPYING for licensing information.  */

#include <string.h>
#include <assert.h>
#include <freeradius/libradius.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#if defined DEBUG
#include <netdb.h>
#include <sys/socket.h>
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
    return rs_err_conn_push (conn, RSE_NOMEM, __func__);
  rpkt->id = -1;

  p = (struct rs_packet *) malloc (sizeof (struct rs_packet));
  if (!p)
    {
      rad_free (&rpkt);
      return rs_err_conn_push (conn, RSE_NOMEM, __func__);
    }
  memset (p, 0, sizeof (struct rs_packet));
  p->conn = conn;
  p->rpkt = rpkt;

  *pkt_out = p;
  return RSE_OK;
}

static void
_do_send (struct rs_packet *pkt)
{
  int err;

  rad_encode (pkt->rpkt, NULL, pkt->conn->active_peer->secret);
  assert (pkt->rpkt);
#if defined (DEBUG)
  {
    char host[80], serv[80];

    getnameinfo (pkt->conn->active_peer->addr->ai_addr,
		 pkt->conn->active_peer->addr->ai_addrlen,
		 host, sizeof(host), serv, sizeof(serv),
		 0 /* NI_NUMERICHOST|NI_NUMERICSERV*/);
    fprintf (stderr, "%s: about to send this to %s:%s:\n", __func__, host,
	     serv);
    rs_dump_packet (pkt);
  }
#endif
  err = bufferevent_write (pkt->conn->bev, pkt->rpkt->data,
			   pkt->rpkt->data_len);
  if (err < 0)
    rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
			 "bufferevent_write: %s", evutil_gai_strerror(err));
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
      _do_send (pkt);
      /* Packet will be freed in write callback.  */
    }
  else if (events & BEV_EVENT_ERROR)
    rs_err_conn_push_fl (pkt->conn, RSE_CONNERR, __FILE__, __LINE__, NULL);
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
      n = bufferevent_read (pkt->conn->bev, pkt->hdr, RS_HEADER_LEN);
      if (n == RS_HEADER_LEN)
	{
	  pkt->hdr_read_flag = 1;
	  pkt->rpkt->data_len = (pkt->hdr[2] << 8) + pkt->hdr[3];
	  if (pkt->rpkt->data_len < 20 /* || len > 4096 */)
	    abort ();		/* FIXME: Read and discard packet.  */
	  pkt->rpkt->data = rs_malloc (pkt->conn->ctx, pkt->rpkt->data_len);
	  if (!pkt->rpkt->data)
	    {
	      rs_err_conn_push_fl (pkt->conn, RSE_NOMEM, __FILE__, __LINE__,
				   NULL);
	      abort ();		/* FIXME: Read and discard packet.  */
	    }
	  memcpy (pkt->rpkt->data, pkt->hdr, RS_HEADER_LEN);
	  bufferevent_setwatermark (pkt->conn->bev, EV_READ,
				    pkt->rpkt->data_len - RS_HEADER_LEN, 0);
#if defined (DEBUG)
	  fprintf (stderr, "%s: packet header read, total pkt len=%d\n",
		   __func__, pkt->rpkt->data_len);
#endif
	}
      else if (n < 0)
	return;			/* Buffer frozen.  */
      else
	assert (!"short header");
    }

#if defined (DEBUG)
  printf ("%s: trying to read %d octets of packet data\n", __func__, pkt->rpkt->data_len - RS_HEADER_LEN);
#endif
  n = bufferevent_read (pkt->conn->bev, pkt->rpkt->data + RS_HEADER_LEN, pkt->rpkt->data_len - RS_HEADER_LEN);
#if defined (DEBUG)
  printf ("%s: read %d octets of packet data\n", __func__, n);
#endif
  if (n == pkt->rpkt->data_len - RS_HEADER_LEN)
    {
      bufferevent_disable (pkt->conn->bev, EV_READ);
      pkt->hdr_read_flag = 0;
      memset (pkt->hdr, 0, sizeof(*pkt->hdr));
#if defined (DEBUG)
      fprintf (stderr, "%s: complete packet read\n", __func__);
#endif
      rad_decode (pkt->rpkt, NULL, pkt->conn->active_peer->secret);
      if (event_base_loopbreak (pkt->conn->evb) < 0)
	abort ();		/* FIXME */
    }
  else if (n < 0)
    return;			/* Buffer frozen.  */
  else
    assert (!"short packet");
}

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
  fprintf (stderr, "libevent: [%s] %s\n", sevstr, msg);
}

static int
_init_evb (struct rs_connection *conn)
{
  if (!conn->evb)
    {
#if defined (DEBUG)
      event_enable_debug_mode ();
#endif
      event_set_log_callback (_evlog_cb);
      conn->evb = event_base_new ();
      if (!conn->evb)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "event_base_new");
    }
  return RSE_OK;
}

static int
_init_socket (struct rs_connection *conn, struct rs_peer *p)
{
  if (p->fd != -1)
    return RSE_OK;

  assert (p->addr);
  p->fd = socket (p->addr->ai_family, p->addr->ai_socktype,
		  p->addr->ai_protocol);
  if (p->fd < 0)
    return rs_err_conn_push_fl (conn, RSE_SOME_ERROR, __FILE__, __LINE__,
				strerror (errno));
  if (evutil_make_socket_nonblocking (p->fd) < 0)
    {
      evutil_closesocket (p->fd);
      return rs_err_conn_push_fl (conn, RSE_SOME_ERROR, __FILE__, __LINE__,
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
      conn->bev = bufferevent_socket_new (conn->evb, peer->fd, 0);
      if (!conn->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_socket_new");
    }
  return RSE_OK;
}

static void
_do_connect (struct rs_peer *p)
{
  int err;

  err = bufferevent_socket_connect (p->conn->bev, p->addr->ai_addr,
				    p->addr->ai_addrlen);
  if (err < 0)
    rs_err_conn_push_fl (p->conn, RSE_EVENT, __FILE__, __LINE__,
			 "bufferevent_socket_connect: %s",
			 evutil_gai_strerror(err));
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
    return rs_err_conn_push_fl (conn, RSE_NOPEER, __FILE__, __LINE__, NULL);

  if (_init_socket (conn, p))
    return -1;

  if (_init_bev (conn, p))
    return -1;

  if (!p->is_connected)
    if (!p->is_connecting)
      _do_connect (p);

  return RSE_OK;
}

static int
_conn_is_open_p (struct rs_connection *conn)
{
  return conn->active_peer && conn->active_peer->is_connected;
}

/* Public functions.  */
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

int
rs_packet_send (struct rs_packet *pkt, void *user_data)
{
  struct rs_connection *conn;
  assert (pkt);
  conn = pkt->conn;

  if (_conn_is_open_p (conn))
    _do_send (pkt);
  else
    if (_conn_open (conn, pkt))
      return -1;

  assert (conn->evb);
  assert (conn->bev);
  assert (conn->active_peer);
  assert (conn->active_peer->fd >= 0);

  if (conn->callbacks.connected_cb || conn->callbacks.disconnected_cb
      || conn->callbacks.received_cb || conn->callbacks.sent_cb)
    ;		/* FIXME: install event callbacks, other than below */
  else
    {
      bufferevent_setcb (conn->bev, _read_cb, _write_cb, _event_cb, pkt);
      event_base_dispatch (conn->evb);
    }

#if defined (DEBUG)
  fprintf (stderr, "%s: event loop done\n", __func__);
  assert (event_base_got_break(conn->evb));
#endif

  return RSE_OK;
}

int
rs_conn_receive_packet (struct rs_connection *conn, struct rs_packet **pkt_out)
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
  assert (conn->active_peer->fd >= 0);

  bufferevent_setwatermark (conn->bev, EV_READ, RS_HEADER_LEN, 0);
  bufferevent_enable (conn->bev, EV_READ);
  event_base_dispatch (conn->evb);
#if defined (DEBUG)
  fprintf (stderr, "%s: event loop done", __func__);
  if (event_base_got_break(conn->evb))
    {
      fprintf (stderr, ", got this:\n");
      rs_dump_packet (pkt);
    }
  else
    fprintf (stderr, ", no reply\n");
#endif

  return RSE_OK;
}

void
rs_packet_add_attr(struct rs_packet *pkt, struct rs_attr *attr)
{
  pairadd (&pkt->rpkt->vps, attr->vp);
  attr->pkt = pkt;
}

struct radius_packet *
rs_packet_frpkt(struct rs_packet *pkt)
{
  assert (pkt);
  return pkt->rpkt;
}

void
rs_packet_destroy(struct rs_packet *pkt)
{
  if (pkt)
    {
      rad_free (&pkt->rpkt);
      rs_free (pkt->conn->ctx, pkt);
    }
}
