/* See the file COPYING for licensing information.  */

#include <time.h>
#include <event2/event.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include <radsec/request.h>
#include <radsec/request-impl.h>

int
rs_req_create (struct rs_connection *conn, struct rs_request **req_out)
{
  struct rs_request *req = rs_malloc (conn->ctx, sizeof(*req));
  if (!req)
    return rs_conn_err_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
  memset (req, 0, sizeof(*req));
  req->conn = conn;
  *req_out = req;
  return RSE_OK;
}

void
rs_req_destroy(struct rs_request *request)
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

int
rs_req_send(struct rs_request *request, struct rs_packet *req,
	    struct rs_packet **resp)
{
  /* install our own callback, backing up any user provided one in
     req->saved_cb*/

  return -1;
}
