/* Copyright 2010,2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

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
#include "message.h"

#if defined (DEBUG)
#include <netdb.h>
#include <sys/socket.h>
#include <event2/buffer.h>
#endif

int
message_verify_response (struct rs_connection *conn,
                         struct rs_message *response,
                         struct rs_message *request)
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
message_do_send (struct rs_message *msg)
{
  int err;

  assert (msg);
  assert (msg->conn);
  assert (msg->conn->active_peer);
  assert (msg->conn->active_peer->secret);
  assert (msg->rpkt);

  msg->rpkt->secret = msg->conn->active_peer->secret;
  msg->rpkt->sizeof_secret = strlen (msg->rpkt->secret);

  /* Encode message.  */
  err = nr_packet_encode (msg->rpkt, NULL);
  if (err < 0)
    return rs_err_conn_push_fl (msg->conn, -err, __FILE__, __LINE__,
				"nr_packet_encode");
  /* Sign message.  */
  err = nr_packet_sign (msg->rpkt, NULL);
  if (err < 0)
    return rs_err_conn_push_fl (msg->conn, -err, __FILE__, __LINE__,
				"nr_packet_sign");
#if defined (DEBUG)
  {
    char host[80], serv[80];

    getnameinfo (msg->conn->active_peer->addr_cache->ai_addr,
		 msg->conn->active_peer->addr_cache->ai_addrlen,
		 host, sizeof(host), serv, sizeof(serv),
		 0 /* NI_NUMERICHOST|NI_NUMERICSERV*/);
    rs_debug (("%s: about to send this to %s:%s:\n", __func__, host, serv));
    rs_dump_message (msg);
  }
#endif

  /* Put message in output buffer.  */
  if (msg->conn->base_.bev)       /* TCP.  */
    {
      int err = bufferevent_write (msg->conn->base_.bev, msg->rpkt->data,
				   msg->rpkt->length);
      if (err < 0)
	return rs_err_conn_push_fl (msg->conn, RSE_EVENT, __FILE__, __LINE__,
				    "bufferevent_write: %s",
				    evutil_gai_strerror (err));
    }
  else				/* UDP.  */
    {
      struct rs_message **pp = &msg->conn->out_queue;

      while (*pp && (*pp)->next)
	*pp = (*pp)->next;
      *pp = msg;
    }

  return RSE_OK;
}

/* Public functions.  */
int
rs_message_create (struct rs_connection *conn, struct rs_message **msg_out)
{
  struct rs_message *p;
  RADIUS_PACKET *rpkt;
  int err;

  *msg_out = NULL;

  rpkt = rs_malloc (conn->base_.ctx, sizeof(*rpkt) + RS_MAX_PACKET_LEN);
  if (rpkt == NULL)
    return rs_err_conn_push (conn, RSE_NOMEM, __func__);

  err = nr_packet_init (rpkt, NULL, NULL,
		        PW_ACCESS_REQUEST,
		        rpkt + 1, RS_MAX_PACKET_LEN);
  if (err < 0)
    return rs_err_conn_push (conn, -err, __func__);

  p = (struct rs_message *) rs_calloc (conn->base_.ctx, 1, sizeof (*p));
  if (p == NULL)
    {
      rs_free (conn->base_.ctx, rpkt);
      return rs_err_conn_push (conn, RSE_NOMEM, __func__);
    }
  p->conn = conn;
  p->rpkt = rpkt;

  *msg_out = p;
  return RSE_OK;
}

int
rs_message_create_authn_request (struct rs_connection *conn,
                                 struct rs_message **msg_out,
                                 const char *user_name,
                                 const char *user_pw,
                                 const char *secret)
{
  struct rs_message *msg;
  int err;

  if (rs_message_create (conn, msg_out))
    return -1;

  msg = *msg_out;
  msg->rpkt->code = PW_ACCESS_REQUEST;

  if (user_name)
    {
      err = rs_message_append_avp (msg, PW_USER_NAME, 0, user_name, 0);
      if (err)
	return err;
    }

  if (user_pw)
    {
      msg->rpkt->secret = secret;
      err = rs_message_append_avp (msg, PW_USER_PASSWORD, 0, user_pw, 0);
      if (err)
	return err;
    }

  return RSE_OK;
}

void
rs_message_destroy (struct rs_message *msg)
{
  assert (msg);
  assert (msg->conn);
  assert (msg->conn->base_.ctx);

  rs_avp_free (&msg->rpkt->vps);
  rs_free (msg->conn->base_.ctx, msg->rpkt);
  rs_free (msg->conn->base_.ctx, msg);
}

int
rs_message_append_avp (struct rs_message *msg,
                       unsigned int attr, unsigned int vendor,
                       const void *data, size_t data_len)
{
  const DICT_ATTR *da;
  int err;

  assert (msg);

  da = nr_dict_attr_byvalue (attr, vendor);
  if (da == NULL)
    return RSE_ATTR_TYPE_UNKNOWN;

  err = nr_packet_attr_append (msg->rpkt, NULL, da, data, data_len);
  if (err < 0)
    return rs_err_conn_push (msg->conn, -err, __func__);

  return RSE_OK;
}

void
rs_message_avps (struct rs_message *msg, rs_avp ***vps)
{
  assert (msg);
  *vps = &msg->rpkt->vps;
}

unsigned int
rs_message_code (struct rs_message *msg)
{
  assert (msg);
  return msg->rpkt->code;
}

rs_const_avp *
rs_message_find_avp (struct rs_message *msg, unsigned int attr, unsigned int vendor)
{
  assert (msg);
  return rs_avp_find_const (msg->rpkt->vps, attr, vendor);
}

int
rs_message_set_id (struct rs_message *msg, int id)
{
  int old = msg->rpkt->id;

  msg->rpkt->id = id;

  return old;
}
