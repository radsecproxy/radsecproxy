/* See the file COPYING for licensing information.  */

#include <time.h>
#include <assert.h>
#include <event2/event.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include <radsec/request.h>
#include <radsec/request-impl.h>

static int
_rs_decrypt_mppe(struct rs_request *request, VALUE_PAIR *vp);

int
rs_request_create (struct rs_connection *conn, struct rs_request **req_out)
{
  struct rs_request *req = rs_malloc (conn->ctx, sizeof(*req));
  if (!req)
    return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
  memset (req, 0, sizeof(*req));
  req->conn = conn;
  *req_out = req;
  return RSE_OK;
}

void
rs_request_destroy (struct rs_request *request)
{
  rs_packet_destroy (request->req);
  rs_packet_destroy (request->resp);
  rs_free (request->conn->ctx, request);
}

#if 0
static void
_timer_cb(evutil_socket_t fd, short what, void *arg)

{
}
#endif

static void
_rs_req_connected(void *user_data)
{
  struct rs_request *request = (struct rs_request *)user_data;
}

static void
_rs_req_disconnected(void *user_data)
{
  struct rs_request *request = (struct rs_request *)user_data;
}

static void
_rs_req_packet_received(const struct rs_packet *pkt, void *user_data)
{
  struct rs_request *request = (struct rs_request *)user_data;
  int err;
  VALUE_PAIR *vp;

  assert (request);
  assert (request->conn);
  assert (request->req);

  err = rad_verify(pkt->rpkt, request->req->rpkt,
		   pkt->conn->active_peer->secret);
  if (err)
    return;

  for (vp = pkt->rpkt->vps; vp != NULL; vp = vp->next)
    {
      if (VENDOR(vp->attribute) != VENDORPEC_MS)
	continue;

      switch (vp->attribute & 0xffff)
	{
	  case PW_MS_MPPE_SEND_KEY:
	  case PW_MS_MPPE_RECV_KEY:
	    err = _rs_decrypt_mppe (request, vp);
	    if (err)
	      return;
	    break;
	  default:
	    break;
	}
    }

  request->verified = 1;
}

static void
_rs_req_packet_sent(void *user_data)
{
  struct rs_request *request = (struct rs_request *)user_data;
}

int
rs_request_send(struct rs_request *request, struct rs_packet *req,
	        struct rs_packet **resp)
{
  int err;
  VALUE_PAIR *vp;
  struct rs_connection *conn;

  assert (request);
  assert (request->conn);
  conn = request->conn;

  request->req = req;		/* take ownership */
  request->saved_cb = conn->callbacks;

  conn->callbacks.connected_cb = _rs_req_connected;
  conn->callbacks.disconnected_cb = _rs_req_disconnected;
  conn->callbacks.received_cb = _rs_req_packet_received;
  conn->callbacks.sent_cb = _rs_req_packet_sent;

  assert(request->verified == 0);

  vp = paircreate(PW_MESSAGE_AUTHENTICATOR, PW_TYPE_OCTETS);
  pairadd(&request->req->rpkt->vps, vp);

  err = rs_packet_send(request->req, request);
  if (err)
    goto cleanup;

  err = rs_conn_receive_packet(request->conn, resp);
  if (err)
    goto cleanup;

  if (!request->verified)
    {
      err = rs_err_conn_push_fl (conn, RSE_BADAUTH, __FILE__, __LINE__, NULL);
      goto cleanup;
    }

cleanup:
  conn->callbacks = request->saved_cb;
  return err;
}

/*
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */
#include <openssl/md5.h>

static int
_rs_decrypt_mppe(struct rs_request *request, VALUE_PAIR *vp)
{
  unsigned char *key = vp->vp_octets;
  size_t len = vp->length;
  unsigned char plain[1 + MAX_STRING_LEN], *ppos = plain, *res;
  const unsigned char *pos;
  size_t left, plen;
  unsigned char hash[MD5_DIGEST_LENGTH];
  int i, first = 1;
  const unsigned char *addr[3];
  struct rs_connection *conn;

  assert (request);
  assert (request->conn);
  conn = request->conn;

  if (vp->type != PW_TYPE_OCTETS)
    return rs_err_conn_push_fl (conn, RSE_BADAUTH, __FILE__, __LINE__, NULL);

  pos = key + 2;
  left = len - 2;
  if (left % 16)
    return rs_err_conn_push_fl (conn, RSE_BADAUTH, __FILE__, __LINE__, NULL);

  plen = left;
  if (plen > MAX_STRING_LEN)
    return rs_err_conn_push_fl (conn, RSE_BADAUTH, __FILE__, __LINE__, NULL);

  plain[0] = 0;

  while (left)
    {
      MD5_CTX md5;

      MD5_Init (&md5);
      MD5_Update (&md5, conn->active_peer->secret,
	          strlen (conn->active_peer->secret));
      if (first)
	{
	  MD5_Update (&md5, request->req->rpkt->vector, MD5_DIGEST_LENGTH);
	  MD5_Update (&md5, key, 2);
	  first = 0;
	}
      else
	{
	  MD5_Update (&md5, pos - MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH);
	}
      MD5_Final (hash, &md5);

      for (i = 0; i < MD5_DIGEST_LENGTH; i++)
	*ppos++ = *pos++ ^ hash[i];
      left -= MD5_DIGEST_LENGTH;
    }

  if (plain[0] == 0 || plain[0] > plen - 1)
    return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);

  memcpy (vp->vp_octets, plain + 1, plain[0]);
  vp->length = plain[0];

  return RSE_OK;
}
