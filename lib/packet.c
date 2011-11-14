/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <radius/client.h>
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
  int err;

  assert (conn);
  assert (conn->active_peer);
  assert (conn->active_peer->secret);
  assert (response);
  assert (response->rpkt);
  assert (request);
  assert (request->rpkt);

  response->rpkt->secret = conn->active_peer->secret;
  response->rpkt->sizeof_secret = strlen (conn->active_peer->secret);

  /* Verify header and message authenticator.  */
  err = nr_packet_verify (response->rpkt, request->rpkt);
  if (err)
    {
      if (conn->is_connected)
	rs_conn_disconnect(conn);
      return rs_err_conn_push_fl (conn, -err, __FILE__, __LINE__,
				  "nr_packet_verify");
    }

  /* Decode and decrypt.  */
  err = nr_packet_decode (response->rpkt, request->rpkt);
  if (err)
    {
      if (conn->is_connected)
	rs_conn_disconnect(conn);
      return rs_err_conn_push_fl (conn, -err, __FILE__, __LINE__,
				  "nr_packet_decode");
    }

  return RSE_OK;
}


/* Badly named function for preparing a RADIUS message and queue it.
   FIXME: Rename.  */
int
packet_do_send (struct rs_packet *pkt)
{
  int err;

  assert (pkt);
  assert (pkt->conn);
  assert (pkt->conn->active_peer);
  assert (pkt->conn->active_peer->secret);
  assert (pkt->rpkt);

  pkt->rpkt->secret = pkt->conn->active_peer->secret;
  pkt->rpkt->sizeof_secret = strlen (pkt->rpkt->secret);

  /* Encode message.  */
  err = nr_packet_encode (pkt->rpkt, NULL);
  if (err < 0)
    return rs_err_conn_push_fl (pkt->conn, -err, __FILE__, __LINE__,
				"nr_packet_encode");
  /* Sign message.  */
  err = nr_packet_sign (pkt->rpkt, NULL);
  if (err < 0)
    return rs_err_conn_push_fl (pkt->conn, -err, __FILE__, __LINE__,
				"nr_packet_sign");
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
				   pkt->rpkt->length);
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
  int err;

  *pkt_out = NULL;

  rpkt = rs_malloc (conn->ctx, sizeof(*rpkt) + RS_MAX_PACKET_LEN);
  if (rpkt == NULL)
    return rs_err_conn_push (conn, RSE_NOMEM, __func__);

  /*
   * This doesn't make sense; the packet identifier is constant for
   * an entire conversation. A separate API should be provided to
   * allow the application to set the packet ID, or a conversation
   * object should group related packets together.
   */
#if 0
  rpkt->id = conn->nextid++
#endif

  err = nr_packet_init (rpkt, NULL, NULL,
		        PW_ACCESS_REQUEST,
		        rpkt + 1, RS_MAX_PACKET_LEN);
  if (err < 0)
    return rs_err_conn_push (conn, -err, __func__);

  p = (struct rs_packet *) rs_calloc (conn->ctx, 1, sizeof (*p));
  if (p == NULL)
    {
      rs_free (conn->ctx, rpkt);
      return rs_err_conn_push (conn, RSE_NOMEM, __func__);
    }
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
  int err;

  if (rs_packet_create (conn, pkt_out))
    return -1;

  pkt = *pkt_out;
  pkt->rpkt->code = PW_ACCESS_REQUEST;

  if (user_name)
    {
      err = rs_packet_append_avp (pkt, PW_USER_NAME, 0, user_name, 0);
      if (err)
	return err;
    }

  if (user_pw)
    {
      err = rs_packet_append_avp (pkt, PW_USER_PASSWORD, 0, user_pw, 0);
      if (err)
	return err;
    }

  return RSE_OK;
}

void
rs_packet_destroy (struct rs_packet *pkt)
{
  assert (pkt);
  assert (pkt->conn);
  assert (pkt->conn->ctx);

  rs_avp_free (&pkt->rpkt->vps);
  rs_free (pkt->conn->ctx, pkt->rpkt);
  rs_free (pkt->conn->ctx, pkt);
}

int
rs_packet_append_avp (struct rs_packet *pkt, 
                      unsigned int attr, unsigned int vendor,
                      const void *data, size_t data_len)
{
  const DICT_ATTR *da;
  int err;

  assert (pkt);

  da = nr_dict_attr_byvalue (attr, vendor);
  if (da == NULL)
    return RSE_ATTR_TYPE_UNKNOWN;

  err = nr_packet_attr_append (pkt->rpkt, NULL, da, data, data_len);
  if (err < 0)
    return rs_err_conn_push (pkt->conn, -err, __func__);

  return RSE_OK;
}

void
rs_packet_avps (struct rs_packet *pkt, rs_avp ***vps)
{
  assert (pkt);
  *vps = &pkt->rpkt->vps;
}

unsigned int
rs_packet_code (struct rs_packet *pkt)
{
  assert (pkt);
  return pkt->rpkt->code;
}

rs_const_avp *
rs_packet_find_avp (struct rs_packet *pkt, unsigned int attr, unsigned int vendor)
{
  assert (pkt);
  return rs_avp_find_const (pkt->rpkt->vps, attr, vendor);
}

int
rs_packet_set_id (struct rs_packet *pkt, int id)
{
  int old = pkt->rpkt->id;

  pkt->rpkt->id = id;

  return old;
}
