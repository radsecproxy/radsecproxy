/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>
#include <assert.h>
#include <event2/event.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include <radsec/request.h>
#include <radsec/request-impl.h>
#include "conn.h"

int
rs_request_create (struct rs_connection *conn, struct rs_request **req_out)
{
  struct rs_request *req = rs_malloc (conn->ctx, sizeof(*req));
  assert (req_out);
  if (!req)
    return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
  memset (req, 0, sizeof(*req));
  req->conn = conn;
  *req_out = req;
  return RSE_OK;
}

void
rs_request_add_reqpkt (struct rs_request *req, struct rs_packet *reqpkt)
{
  assert (req);
  req->req_msg = reqpkt;
}

int
rs_request_create_authn (struct rs_connection *conn,
			 struct rs_request **req_out,
			 const char *user_name,
			 const char *user_pw)
{
  struct rs_request *req;
  assert (req_out);
  if (rs_request_create (conn, &req))
    return -1;

  if (rs_packet_create_authn_request (conn, &req->req_msg, user_name, user_pw))
    return -1;

  *req_out = req;
  return RSE_OK;
}

void
rs_request_destroy (struct rs_request *request)
{
  assert (request);
  rs_packet_destroy (request->req_msg);
  rs_packet_destroy (request->resp_msg);
  rs_free (request->conn->ctx, request);
}

#if 0
static void
_timer_cb (evutil_socket_t fd, short what, void *arg)

{
}
#endif

int
rs_request_send (struct rs_request *request, struct rs_packet **resp_msg)
{
  struct rs_connection *conn = NULL;

  if (!request || !request->conn || !request->req_msg || !resp_msg)
    return rs_err_conn_push_fl (conn, RSE_INVAL, __FILE__, __LINE__, NULL);
  conn = request->conn;
  assert (!conn_user_dispatch_p (conn)); /* This function is high level.  */

  if (rs_packet_send (request->req_msg, request))
    return -1;

  if (rs_conn_receive_packet (request->conn, request->req_msg, resp_msg))
    return -1;

  return RSE_OK;
}
