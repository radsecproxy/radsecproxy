/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <freeradius/libradius.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#if defined RS_ENABLE_TLS
#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>
#endif
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "tls.h"
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
  rpkt->id = conn->nextid++;

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

static int
_do_send (struct rs_packet *pkt)
{
  int err;
  VALUE_PAIR *vp;

  assert (pkt->rpkt);
  assert (!pkt->original);

  vp = paircreate (PW_MESSAGE_AUTHENTICATOR, PW_TYPE_OCTETS);
  if (!vp)
    return rs_err_conn_push_fl (pkt->conn, RSE_NOMEM, __FILE__, __LINE__,
				"paircreate: %s", fr_strerror ());
  pairadd (&pkt->rpkt->vps, vp);

  if (rad_encode (pkt->rpkt, NULL, pkt->conn->active_peer->secret))
    return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
				"rad_encode: %s", fr_strerror ());
  if (rad_sign (pkt->rpkt, NULL, pkt->conn->active_peer->secret))
    return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
				"rad_sign: %s", fr_strerror ());
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
    return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				"bufferevent_write: %s",
				evutil_gai_strerror(err));
  return RSE_OK;
}

static void
_event_cb (struct bufferevent *bev, short events, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *)ctx;
  struct rs_connection *conn;
  struct rs_peer *p;
#if defined RS_ENABLE_TLS
  unsigned long err;
#endif

  assert (pkt);
  assert (pkt->conn);
  assert (pkt->conn->active_peer);
  conn = pkt->conn;
  p = conn->active_peer;

  p->is_connecting = 0;
  if (events & BEV_EVENT_CONNECTED)
    {
      p->is_connected = 1;
      if (conn->callbacks.connected_cb)
	conn->callbacks.connected_cb (conn->user_data);
#if defined (DEBUG)
      fprintf (stderr, "%s: connected\n", __func__);
#endif
      if (_do_send (pkt))
	return;
      if (conn->callbacks.sent_cb)
	conn->callbacks.sent_cb (conn->user_data);
      /* Packet will be freed in write callback.  */
    }
  else if (events & BEV_EVENT_ERROR)
    {
#if defined RS_ENABLE_TLS
      if (conn->tls_ssl)	/* FIXME: correct check?  */
	{
	  for (err = bufferevent_get_openssl_error (conn->bev);
	       err;
	       err = bufferevent_get_openssl_error (conn->bev))
	    {
	      fprintf (stderr, "%s: openssl error: %s\n", __func__,
		       ERR_error_string (err, NULL)); /* DEBUG, until verified that pushed errors will actually be handled  */
	      rs_err_conn_push_fl (pkt->conn, RSE_SSLERR, __FILE__, __LINE__,
				   "%d", err);
	    }
	}
#endif	/* RS_ENABLE_TLS */
      rs_err_conn_push_fl (pkt->conn, RSE_CONNERR, __FILE__, __LINE__, NULL);
      fprintf (stderr, "%s: BEV_EVENT_ERROR\n", __func__); /* DEBUG, until verified that pushed errors will actually be handled  */
    }
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
  if (!pkt->conn->callbacks.sent_cb) /* Callback owns the packet now.  */
    rs_packet_destroy (pkt);
}

static void
_read_cb (struct bufferevent *bev, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *)ctx;
  size_t n;

  assert (pkt);
  assert (pkt->conn);

  pkt->rpkt->sockfd = pkt->conn->active_peer->fd; /* FIXME: Why?  */
  pkt->rpkt->vps = NULL;			  /* FIXME: Why?  */

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
      if (!rad_packet_ok (pkt->rpkt, 0) != 0)
	return;
      assert (pkt->original);

      /* Verify header and message authenticator.  */
      if (rad_verify (pkt->rpkt, pkt->original->rpkt,
		      pkt->conn->active_peer->secret))
	{
	  rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
			       "rad_verify: %s", fr_strerror ());
	  return;
	}

      /* Decode and decrypt.  */
      if (rad_decode (pkt->rpkt, pkt->original->rpkt,
		      pkt->conn->active_peer->secret))
	{
	  rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
			       "rad_decode: %s", fr_strerror ());
	  return;
	}

      if (pkt->conn->callbacks.received_cb)
	pkt->conn->callbacks.received_cb (pkt, pkt->conn->user_data);

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
  if (conn->bev)
    return RSE_OK;

  switch (conn->type)
    {
    case RS_CONN_TYPE_UDP:
    case RS_CONN_TYPE_TCP:
      conn->bev = bufferevent_socket_new (conn->evb, peer->fd, 0);
      if (!conn->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_socket_new");
      break;
#if defined RS_ENABLE_TLS
    case RS_CONN_TYPE_TLS:
      if (rs_tls_init (conn))
	return -1;
      /* Would be convenient to pass BEV_OPT_CLOSE_ON_FREE but things
	 seem to break when be_openssl_ctrl() (in libevent) calls
	 SSL_set_bio() after BIO_new_socket() with flag=1.  */
      conn->bev =
	bufferevent_openssl_socket_new (conn->evb, peer->fd, conn->tls_ssl,
					BUFFEREVENT_SSL_CONNECTING, 0);
      if (!conn->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_openssl_socket_new");

      break;
    case RS_CONN_TYPE_DTLS:
      return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
				  "%s: NYI", __func__);
#endif	/* RS_ENABLE_TLS */
    default:
      return rs_err_conn_push_fl (conn, RSE_INTERNAL, __FILE__, __LINE__,
				  "%s: unknown connection type: %d", __func__,
				  conn->type);
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

  if (user_name)
    {
      if (rs_attr_create (conn, &attr, "User-Name", user_name))
	return -1;
      rs_packet_add_attr (pkt, attr);

      if (user_pw)
	{
	  if (rs_attr_create (conn, &attr, "User-Password", user_pw))
	    return -1;
	  rs_packet_add_attr (pkt, attr);
	}
    }

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

  conn->user_data = user_data;
  bufferevent_setcb (conn->bev, _read_cb, _write_cb, _event_cb, pkt);
  if (!conn->user_dispatch_flag)
    event_base_dispatch (conn->evb);

#if defined (DEBUG)
  fprintf (stderr, "%s: event loop done\n", __func__);
  assert (event_base_got_break(conn->evb));
#endif

  return RSE_OK;
}

int
rs_conn_receive_packet (struct rs_connection *conn,
		        struct rs_packet *request,
		        struct rs_packet **pkt_out)
{
  struct rs_packet *pkt;

  assert (conn);

  if (_packet_create (conn, pkt_out))
    return -1;
  pkt = *pkt_out;
  pkt->conn = conn;
  pkt->original = request;

  if (_conn_open (conn, pkt))
    return -1;
  assert (conn->evb);
  assert (conn->bev);
  assert (conn->active_peer);
  assert (conn->active_peer->fd >= 0);

  bufferevent_setwatermark (conn->bev, EV_READ, RS_HEADER_LEN, 0);
  bufferevent_enable (conn->bev, EV_READ);
  bufferevent_setcb (conn->bev, _read_cb, _write_cb, _event_cb, pkt);

  if (!conn->user_dispatch_flag)
    {
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
    }

  pkt->original = NULL;

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
      // TODO: free all attributes
      rad_free (&pkt->rpkt);
      rs_free (pkt->conn->ctx, pkt);
    }
}
