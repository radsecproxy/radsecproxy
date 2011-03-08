/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <event2/event.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include <radsec/request.h>
#include <radsec/request-impl.h>
#include <freeradius/libradius.h>
#include "debug.h"
#include "conn.h"
#include "tcp.h"

/* RFC 5080 2.2.1.  Retransmission Behavior.  */
#define IRT 2
#define MRC 5
#define MRT 16
#define MRD 30
#define RAND 100		/* Rand factor, milliseconds. */

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

static void
_rand_rt (struct timeval *res, uint32_t rtprev, uint32_t factor)
{
  uint32_t ms = rtprev * (fr_rand () % factor);
  res->tv_sec = rtprev + ms / 1000;
  res->tv_usec = (ms % 1000) * 1000;
}

int
rs_request_send (struct rs_request *request, struct rs_packet **resp_msg)
{
  int r = 0;
  struct rs_connection *conn = NULL;
  int count = 0;
  struct timeval rt = {0,0};
  struct timeval end = {0,0};
  struct timeval now = {0,0};
  struct timeval tmp_tv = {0,0};
  struct timeval mrt_tv = {MRT,0};

  if (!request || !request->conn || !request->req_msg || !resp_msg)
    return rs_err_conn_push_fl (conn, RSE_INVAL, __FILE__, __LINE__, NULL);
  conn = request->conn;
  assert (!conn_user_dispatch_p (conn)); /* This function is high level.  */

  gettimeofday (&end, NULL);
  end.tv_sec += MRD;
  _rand_rt (&rt, IRT, RAND);
  while (1)
    {
      rs_conn_set_timeout (conn, &rt);
      r = rs_packet_send (request->req_msg, NULL);
      if (r == RSE_OK)
	{
	  r = rs_conn_receive_packet (request->conn,
				      request->req_msg,
				      resp_msg);
	  if (r == RSE_OK)
	    break;		/* Success.  */

	  /* Timing out on receiving data or reconnecting a broken TCP
	     connection is ok.  */
	  if (r != RSE_TIMEOUT_CONN && r != RSE_TIMEOUT_IO)
	    break;		/* Error.  */
	}
      else if (r != RSE_TIMEOUT_CONN) /* Timeout on TCP connect is ok.  */
	break;			      /* Error.  */

      gettimeofday (&now, NULL);
      if (++count > MRC || timercmp (&now, &end, >))
	{
	  r = RSE_TIMEOUT;
	  break;		/* Timeout.  */
	}

      /* rt = 2 * rt + _rand_rt (rt, RAND); */
      timeradd (&rt, &rt, &rt);	/* rt = 2 * rt */
      _rand_rt (&tmp_tv, IRT, RAND);
      timeradd (&rt, &tmp_tv, &rt);
      if (timercmp (&rt, &mrt_tv, >))
	_rand_rt (&rt, MRT, RAND);
    }

  rs_debug (("%s: returning %d\n", __func__, r));
  return r;
}
