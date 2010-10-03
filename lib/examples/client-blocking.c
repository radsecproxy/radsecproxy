/* RADIUS client doing blocking i/o.  */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <event2/event.h>
#include <freeradius/libradius.h>
#include <radsec/radsec.h>
#if defined(USE_REQUEST_OBJECT)
#include <radsec/request.h>
#endif

#define SECRET "sikrit"
#define USER_NAME "bob"
#define USER_PW "hemligt"

struct rs_error *
rsx_client (const char *srvname, int srvport)
{
  struct rs_handle *h;
  struct rs_connection *conn;
  struct rs_peer *server;
  struct rs_packet *req, *resp;
  RADIUS_PACKET *fr_pkt;
  VALUE_PAIR *fr_vp;

  if (rs_context_create (&h, "/usr/share/freeradius/dictionary"))
    return NULL;

  if (rs_conn_create (h, &conn))
    return rs_conn_err_pop (conn);
  if (rs_conn_add_server (conn, &server, RS_CONN_TYPE_UDP, srvname, srvport))
    return rs_conn_err_pop (conn);
  rs_server_set_timeout (server, 1);
  rs_server_set_tries (server, 3);
  rs_server_set_secret (server, SECRET);

  if (rs_packet_create_acc_request (conn, &req, USER_NAME, USER_PW))
    return rs_conn_err_pop (conn);

#if !defined(USE_REQUEST_OBJECT)
  if (rs_packet_send (req, NULL))
    return rs_conn_err_pop (conn);
  req = NULL;
  if (rs_conn_receive_packet (conn, &resp))
    return rs_conn_err_pop (conn);
#else
  {
    struct rs_request *request;

    if (rs_request_new (conn, &request))
      return rs_conn_err_pop (conn);
    if (rs_req_send (request, req, &resp))
      return rs_conn_err_pop (conn);
    rs_request_destroy (request);
  }
#endif /* !defined(USE_REQUEST_OBJECT) */

  fr_pkt = rs_packet_frpkt (resp);
  fr_vp = fr_pkt->vps;		/* FIXME: Is there an accessor?  */
  vp_printlist(stdout, fr_vp);
  rs_packet_destroy (resp);

  rs_conn_destroy (conn);
  rs_context_destroy (h);
  return NULL;
}

int
main (int argc, char *argv[])
{
  struct rs_error *err;
  char *host;
  int port;

  host = strsep (argv + 1, ":");
  port = atoi (argv[1]);
  err = rsx_client (host, port);
  if (err)
    {
      fprintf (stderr, "%s\n", rs_err_msg (err, 0));
      return rs_err_code (err, 1);
    }
  return 0;
}
