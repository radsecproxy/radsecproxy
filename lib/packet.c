/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <event2/bufferevent.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "conn.h"
#include "debug.h"
#include "packet.h"

#if defined (DEBUG)
#include <netdb.h>
#include <sys/socket.h>
#include <event2/buffer.h>
#endif

int
packet_verify_response (struct rs_connection *conn,
			struct rs_packet *response,
			struct rs_packet *request)
{
  assert (conn);
  assert (conn->active_peer);
  assert (conn->active_peer->secret);
  assert (response);
  assert (response->rpkt);
  assert (request);
  assert (request->rpkt);

  /* Verify header and message authenticator.  */
  if (rad_verify (response->rpkt, request->rpkt, conn->active_peer->secret))
    {
      conn_close (&conn);
      return rs_err_conn_push_fl (conn, RSE_FR, __FILE__, __LINE__,
				  "rad_verify: %s", fr_strerror ());
    }

  /* Decode and decrypt.  */
  if (rad_decode (response->rpkt, request->rpkt, conn->active_peer->secret))
    {
      conn_close (&conn);
      return rs_err_conn_push_fl (conn, RSE_FR, __FILE__, __LINE__,
				  "rad_decode: %s", fr_strerror ());
    }

  return RSE_OK;
}


/* Badly named function for preparing a RADIUS message and queue it.
   FIXME: Rename.  */
int
packet_do_send (struct rs_packet *pkt)
{
  VALUE_PAIR *vp = NULL;

  assert (pkt);
  assert (pkt->conn);
  assert (pkt->conn->active_peer);
  assert (pkt->conn->active_peer->secret);
  assert (pkt->rpkt);

  /* Add a Message-Authenticator, RFC 2869, if not already present.  */
  /* FIXME: Make Message-Authenticator optional?  */
  vp = paircreate (PW_MESSAGE_AUTHENTICATOR, PW_TYPE_OCTETS);
  if (!vp)
    return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
				"paircreate: %s", fr_strerror ());
  pairreplace (&pkt->rpkt->vps, vp);

  /* Encode message.  */
  if (rad_encode (pkt->rpkt, NULL, pkt->conn->active_peer->secret))
    return rs_err_conn_push_fl (pkt->conn, RSE_FR, __FILE__, __LINE__,
				"rad_encode: %s", fr_strerror ());
  /* Sign message.  */
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

  /* Put message in output buffer.  */
  if (pkt->conn->bev)		/* TCP.  */
    {
      int err = bufferevent_write (pkt->conn->bev, pkt->rpkt->data,
				   pkt->rpkt->data_len);
      if (err < 0)
	return rs_err_conn_push_fl (pkt->conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_write: %s",
				    evutil_gai_strerror (err));
    }
  else				/* UDP.  */
    {
      struct rs_packet **pp = &pkt->conn->out_queue;

      while (*pp && (*pp)->next)
	*pp = (*pp)->next;
      *pp = pkt;
    }

  return RSE_OK;
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
rs_packet_create_authn_request (struct rs_connection *conn,
				struct rs_packet **pkt_out,
				const char *user_name, const char *user_pw)
{
  struct rs_packet *pkt;
  VALUE_PAIR *vp = NULL;

  if (rs_packet_create (conn, pkt_out))
    return -1;
  pkt = *pkt_out;
  pkt->rpkt->code = PW_AUTHENTICATION_REQUEST;

  if (user_name)
    {
      vp = pairmake ("User-Name", user_name, T_OP_EQ);
      if (vp == NULL)
	return rs_err_conn_push_fl (conn, RSE_FR, __FILE__, __LINE__,
				    "pairmake: %s", fr_strerror ());
      pairadd (&pkt->rpkt->vps, vp);
    }

  if (user_pw)
    {
      vp = pairmake ("User-Password", user_pw, T_OP_EQ);
      if (vp == NULL)
	return rs_err_conn_push_fl (conn, RSE_FR, __FILE__, __LINE__,
				    "pairmake: %s", fr_strerror ());
      pairadd (&pkt->rpkt->vps, vp);
    }

  return RSE_OK;
}

struct radius_packet *
rs_packet_frpkt (struct rs_packet *pkt)
{
  assert (pkt);
  return pkt->rpkt;
}

void
rs_packet_destroy (struct rs_packet *pkt)
{
  assert (pkt);
  assert (pkt->conn);
  assert (pkt->conn->ctx);

  rad_free (&pkt->rpkt); /* Note: This frees the VALUE_PAIR's too.  */
  rs_free (pkt->conn->ctx, pkt);
}
