/* See the file COPYING for licensing information.  */

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
  //struct rs_request *request = (struct rs_request *)user_data;
}

static void
_rs_req_disconnected(void *user_data)
{
  //struct rs_request *request = (struct rs_request *)user_data;
}

static void
_rs_req_packet_received(const struct rs_packet *pkt, void *user_data)
{
  //struct rs_request *request = (struct rs_request *)user_data;
}

static void
_rs_req_packet_sent(void *user_data)
{
  //struct rs_request *request = (struct rs_request *)user_data;
}

int
rs_request_send(struct rs_request *request, struct rs_packet *req,
	        struct rs_packet **resp)
{
  int err;
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

  err = rs_packet_send(request->req, request);
  if (err)
    goto cleanup;

  err = rs_conn_receive_packet(request->conn, request->req, resp);
  if (err)
    goto cleanup;

cleanup:
  conn->callbacks = request->saved_cb;
  return err;
}
