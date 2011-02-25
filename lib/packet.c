/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <freeradius/libradius.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "tls.h"
#include "debug.h"
#if defined (RS_ENABLE_TLS)
#include <event2/bufferevent_ssl.h>
#include <openssl/err.h>
#endif
#if defined (DEBUG)
#include <netdb.h>
#include <sys/socket.h>
#include <event2/buffer.h>
#endif

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
    rs_debug (("%s: about to send this to %s:%s:\n", __func__, host, serv));
    rs_dump_packet (pkt);
  }
#endif

  err = bufferevent_write (pkt->conn->bev, pkt->rpkt->data,
			   pkt->rpkt->data_len);
  if (err < 0)
    return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				"bufferevent_write: %s",
				evutil_gai_strerror (err));
  return RSE_OK;
}

static void
_on_connect (struct rs_connection *conn)
{
  conn->is_connected = 1;
  rs_debug (("%s: %p connected\n", __func__, conn->active_peer));
  if (conn->callbacks.connected_cb)
    conn->callbacks.connected_cb (conn->user_data);
}

static void
_on_disconnect (struct rs_connection *conn)
{
  conn->is_connecting = 0;
  conn->is_connected = 0;
  rs_debug (("%s: %p disconnected\n", __func__, conn->active_peer));
  if (conn->callbacks.disconnected_cb)
    conn->callbacks.disconnected_cb (conn->user_data);
}

static void
_event_cb (struct bufferevent *bev, short events, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *)ctx;
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
      _on_connect (conn);
      if (_do_send (pkt))
	rs_debug (("%s: error sending\n", __func__));
    }
  else if (events & BEV_EVENT_EOF)
    {
      _on_disconnect (conn);
    }
  else if (events & BEV_EVENT_TIMEOUT)
    {
      rs_debug (("%s: %p times out on %s\n", __func__, p,
		 (events & BEV_EVENT_READING) ? "read" : "write"));
      rs_err_conn_push_fl (pkt->conn, RSE_IOTIMEOUT, __FILE__, __LINE__, NULL);
    }
  else if (events & BEV_EVENT_ERROR)
    {
      sockerr = evutil_socket_geterror (conn->active_peer->fd);
      if (sockerr == 0)	/* FIXME: True that errno == 0 means closed? */
	{
	  _on_disconnect (conn);
	}
      else
	{
	  rs_err_conn_push_fl (pkt->conn, RSE_SOCKERR, __FILE__, __LINE__,
			       "%d: socket error %d (%s)",
			       conn->fd,
			       sockerr,
			       evutil_socket_error_to_string (sockerr));
	  rs_debug (("%s: socket error on fd %d: %s (%d)\n", __func__,
		     conn->fd,
		     evutil_socket_error_to_string (sockerr),
		     sockerr));
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
    }

#if defined (DEBUG)
  if (events & BEV_EVENT_ERROR && events != BEV_EVENT_ERROR)
    rs_debug (("%s: BEV_EVENT_ERROR and more: 0x%x\n", __func__, events));
#endif
}

static void
_write_cb (struct bufferevent *bev, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *) ctx;

  assert (pkt);
  assert (pkt->conn);

  if (pkt->conn->callbacks.sent_cb)
    pkt->conn->callbacks.sent_cb (pkt->conn->user_data);
}

/* Read one RADIUS packet header.  Return !0 on error.  A return value
   of 0 means that we need more data.  */
static int
_read_header (struct rs_packet *pkt)
{
  size_t n = 0;

  n = bufferevent_read (pkt->conn->bev, pkt->hdr, RS_HEADER_LEN);
  if (n == RS_HEADER_LEN)
    {
      pkt->hdr_read_flag = 1;
      pkt->rpkt->data_len = (pkt->hdr[2] << 8) + pkt->hdr[3];
      if (pkt->rpkt->data_len < 20 || pkt->rpkt->data_len > 4096)
	{
	  bufferevent_free (pkt->conn->bev); /* Close connection.  */
	  return rs_err_conn_push (pkt->conn, RSE_INVALID_PKT,
				   "invalid packet length: %d",
				   pkt->rpkt->data_len);
	}
      pkt->rpkt->data = rs_malloc (pkt->conn->ctx, pkt->rpkt->data_len);
      if (!pkt->rpkt->data)
	{
	  bufferevent_free (pkt->conn->bev); /* Close connection.  */
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
      bufferevent_free (pkt->conn->bev); /* Close connection.  */
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
      pkt->hdr_read_flag = 0;
      memset (pkt->hdr, 0, sizeof(*pkt->hdr));

      /* Checks done by rad_packet_ok:
	 - lenghts (FIXME: checks really ok for tcp?)
	 - invalid code field
	 - attribute lengths >= 2
	 - attribute sizes adding up correctly  */
      if (!rad_packet_ok (pkt->rpkt, 0) != 0)
	{
	  bufferevent_free (pkt->conn->bev); /* Close connection.  */
	  return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
				      "invalid packet: %s", fr_strerror ());
	}

      /* TODO: Verify that reception of an unsolicited response packet
	 results in connection being closed.  */

      /* If we have a request to match this response against, verify
	 and decode the response.  */
      if (pkt->original)
	{
	  /* Verify header and message authenticator.  */
	  if (rad_verify (pkt->rpkt, pkt->original->rpkt,
			  pkt->conn->active_peer->secret))
	    {
	      bufferevent_free (pkt->conn->bev); /* Close connection.  */
	      return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
					  "rad_verify: %s", fr_strerror ());
	    }

	  /* Decode and decrypt.  */
	  if (rad_decode (pkt->rpkt, pkt->original->rpkt,
			  pkt->conn->active_peer->secret))
	    {
	      bufferevent_free (pkt->conn->bev); /* Close connection.  */
	      return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
					  "rad_decode: %s", fr_strerror ());
	    }
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

      /* Hand over message to user, changes ownership of pkt.  Don't
	 touch it afterwards -- it might have been freed.  */
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

/* Read callback for TCP.

   Read exactly one RADIUS message from BEV and store it in struct
   rs_packet passed in CTX (hereby called 'pkt').

   Verify the received packet against pkt->original, if !NULL.

   Inform upper layer about successful reception of valid RADIUS
   message by invoking conn->callbacks.recevied_cb(), if !NULL.  */
static void
_read_cb (struct bufferevent *bev, void *ctx)
{
  struct rs_packet *pkt = (struct rs_packet *) ctx;

  assert (pkt);
  assert (pkt->conn);
  assert (pkt->rpkt);

  pkt->rpkt->sockfd = pkt->conn->fd;
  pkt->rpkt->vps = NULL;

  if (!pkt->hdr_read_flag)
    if (_read_header (pkt))
      return;
  _read_packet (pkt);
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
  fprintf (stderr, "libevent: [%s] %s\n", sevstr, msg); /* FIXME: stderr?  */
}

static int
_init_evb (struct rs_connection *conn)
{
  if (conn->evb)
    return RSE_OK;

#if defined (DEBUG)
  event_enable_debug_mode ();
#endif
  event_set_log_callback (_evlog_cb);
  conn->evb = event_base_new ();
  if (!conn->evb)
    return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				"event_base_new");

  return RSE_OK;
}

static int
_init_socket (struct rs_connection *conn, struct rs_peer *p)
{
  if (conn->fd != -1)
    return RSE_OK;

  assert (p->addr);
  conn->fd = socket (p->addr->ai_family, p->addr->ai_socktype,
		     p->addr->ai_protocol);
  if (conn->fd < 0)
    return rs_err_conn_push_fl (conn, RSE_SOME_ERROR, __FILE__, __LINE__,
				strerror (errno));
  if (evutil_make_socket_nonblocking (conn->fd) < 0)
    {
      evutil_closesocket (conn->fd);
      conn->fd = -1;
      return rs_err_conn_push_fl (conn, RSE_SOME_ERROR, __FILE__, __LINE__,
				  strerror (errno));
    }
  return RSE_OK;
}

static struct rs_peer *
_pick_peer (struct rs_connection *conn)
{
  assert (conn);

  if (conn->active_peer)
    conn->active_peer = conn->active_peer->next; /* Next.  */
  if (!conn->active_peer)
    conn->active_peer = conn->peers; /* From the top.  */

  return conn->active_peer;
}

static int
_init_bev (struct rs_connection *conn, struct rs_peer *peer)
{
  if (conn->bev)
    return RSE_OK;

  switch (conn->realm->type)
    {
    case RS_CONN_TYPE_UDP:
      /* Fall through.  */
      /* NOTE: We know this is wrong for several reasons, most notably
	 because libevent doesn't work as expected with UDP.  The
	 timeout handling is wrong too.  */
    case RS_CONN_TYPE_TCP:
      conn->bev = bufferevent_socket_new (conn->evb, conn->fd, 0);
      if (!conn->bev)
	return rs_err_conn_push_fl (conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_socket_new");
      break;

#if defined (RS_ENABLE_TLS)
    case RS_CONN_TYPE_TLS:
      if (rs_tls_init (conn))
	return -1;
      /* Would be convenient to pass BEV_OPT_CLOSE_ON_FREE but things
	 seem to break when be_openssl_ctrl() (in libevent) calls
	 SSL_set_bio() after BIO_new_socket() with flag=1.  */
      conn->bev =
	bufferevent_openssl_socket_new (conn->evb, conn->fd, conn->tls_ssl,
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
				  conn->realm->type);
    }

  return RSE_OK;
}

static void
_do_connect (struct rs_connection *conn)
{
  struct rs_peer *p;
  int err;

  assert (conn);
  assert (conn->active_peer);
  p = conn->active_peer;

#if defined (DEBUG)
  {
    char host[80], serv[80];

    getnameinfo (p->addr->ai_addr,
		 p->addr->ai_addrlen,
		 host, sizeof(host), serv, sizeof(serv),
		 0 /* NI_NUMERICHOST|NI_NUMERICSERV*/);
    rs_debug (("%s: connecting to %s:%s\n", __func__, host, serv));
  }
#endif

  err = bufferevent_socket_connect (p->conn->bev, p->addr->ai_addr,
				    p->addr->ai_addrlen);
  if (err < 0)
    rs_err_conn_push_fl (p->conn, RSE_EVENT, __FILE__, __LINE__,
			 "bufferevent_socket_connect: %s",
			 evutil_gai_strerror (err));
  else
    p->conn->is_connecting = 1;
}

static int
_conn_open(struct rs_connection *conn, struct rs_packet *pkt)
{
  if (_init_evb (conn))
    return -1;

  if (!conn->active_peer)
    _pick_peer (conn);
  if (!conn->active_peer)
    return rs_err_conn_push_fl (conn, RSE_NOPEER, __FILE__, __LINE__, NULL);

  if (_init_socket (conn, conn->active_peer))
    return -1;

  if (_init_bev (conn, conn->active_peer))
    return -1;

  if (!conn->is_connected)
    if (!conn->is_connecting)
      _do_connect (conn);

  return RSE_OK;
}

static int
_conn_is_open_p (struct rs_connection *conn)
{
  return conn->active_peer && conn->is_connected;
}

/* Public functions.  */
int
rs_packet_create (struct rs_connection *conn, struct rs_packet **pkt_out)
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

int
rs_packet_create_auth_request (struct rs_connection *conn,
			       struct rs_packet **pkt_out,
			       const char *user_name, const char *user_pw)
{
  struct rs_packet *pkt;
  struct rs_attr *attr;

  if (rs_packet_create (conn, pkt_out))
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

/* User callback used when we're dispatching for user.  */
static void
_wcb (void *user_data)
{
  struct rs_packet *pkt = (struct rs_packet *) user_data;
  assert (pkt);
  pkt->written_flag = 1;
  bufferevent_disable (pkt->conn->bev, EV_WRITE|EV_READ);
}

int
rs_packet_send (struct rs_packet *pkt, void *user_data)
{
  struct rs_connection *conn = NULL;
  int err = 0;

  assert (pkt);
  assert (pkt->conn);
  conn = pkt->conn;

  if (_conn_is_open_p (conn))
    _do_send (pkt);
  else
    if (_conn_open (conn, pkt))
      return -1;

  assert (conn->evb);
  assert (conn->bev);
  assert (conn->active_peer);
  assert (conn->fd >= 0);

  conn->user_data = user_data;
  bufferevent_setcb (conn->bev, NULL, _write_cb, _event_cb, pkt);
  bufferevent_enable (conn->bev, EV_WRITE);

  /* Do dispatch, unless the user wants to do it herself.  */
  if (!conn->user_dispatch_flag)
    {
      conn->callbacks.sent_cb = _wcb;
      conn->user_data = pkt;
      rs_debug (("%s: entering event loop\n", __func__));
      err = event_base_dispatch (conn->evb);
      if (err < 0)
	return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				    "event_base_dispatch: %s",
				    evutil_gai_strerror (err));
      rs_debug (("%s: event loop done\n", __func__));
      conn->callbacks.sent_cb = NULL;
      conn->user_data = NULL;

      if (!pkt->written_flag)
	return -1;
    }

  return RSE_OK;
}

static void
_rcb (struct rs_packet *packet, void *user_data)
{
  struct rs_packet *pkt = (struct rs_packet *) user_data;
  assert (pkt);
  pkt->valid_flag = 1;
  bufferevent_disable (pkt->conn->bev, EV_WRITE|EV_READ);
}

/* Special function used in libradsec blocking dispatching mode,
   i.e. with socket set to block on read/write and with no libradsec
   callbacks registered.

   For any other use of libradsec, a the received_cb callback should
   be registered in the callbacks member of struct rs_connection.

   On successful reception, verification and decoding of a RADIUS
   message, PKT_OUT will upon return point at a pointer to a struct
   rs_packet containing the message.

   If anything goes wrong or if the read times out (TODO: explain),
   PKT_OUT will point at the NULL pointer and one or more errors are
   pushed on the connection (available through rs_err_conn_pop()).  */

int
rs_conn_receive_packet (struct rs_connection *conn,
		        struct rs_packet *request,
		        struct rs_packet **pkt_out)
{
  int err = 0;
  struct rs_packet *pkt = NULL;

  assert (conn);
  assert (conn->realm);
  assert (!conn->user_dispatch_flag); /* Dispatching mode only.  */

  if (rs_packet_create (conn, pkt_out))
    return -1;
  pkt = *pkt_out;
  pkt->conn = conn;
  pkt->original = request;

  assert (conn->evb);
  assert (conn->bev);
  assert (conn->active_peer);
  assert (conn->fd >= 0);

  bufferevent_setwatermark (conn->bev, EV_READ, RS_HEADER_LEN, 0);
  bufferevent_setcb (conn->bev, _read_cb, NULL, _event_cb, pkt);
  bufferevent_enable (conn->bev, EV_READ);
  conn->callbacks.received_cb = _rcb;
  conn->user_data = pkt;

  /* Dispatch.  */
  rs_debug (("%s: entering event loop\n", __func__));
  err = event_base_dispatch (conn->evb);
  conn->callbacks.received_cb = NULL;
  if (err < 0)
    return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				"event_base_dispatch: %s",
				evutil_gai_strerror (err));
  rs_debug (("%s: event loop done\n", __func__));

  if (!pkt->valid_flag)
    return -1;

#if defined (DEBUG)
      rs_dump_packet (pkt);
#endif

  pkt->original = NULL;		/* FIXME: Why?  */
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
      // FIXME: memory leak! TODO: free all attributes
      rad_free (&pkt->rpkt);
      rs_free (pkt->conn->ctx, pkt);
    }
}
