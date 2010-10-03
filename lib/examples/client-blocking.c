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
blocking_client (const char *av1, const char *av2)
{
  struct rs_handle *h;
  struct rs_connection *conn;
  struct rs_packet *req, *resp;
  RADIUS_PACKET *fr_pkt;
  VALUE_PAIR *fr_vp;

  if (rs_context_create (&h, "/usr/share/freeradius/dictionary"))
    return NULL;

#if !defined (USE_CONFIG_FILE)
  {
    struct rs_peer *server;

    if (rs_conn_create (h, &conn, NULL))
      return rs_err_conn_pop (conn);
    rs_conn_set_type (conn, RS_CONN_TYPE_UDP);
    if (rs_server_create (conn, &server))
      return rs_err_conn_pop (conn);
    if (rs_server_set_address (server, av1, av2))
      return rs_err_conn_pop (conn);
    rs_server_set_timeout (server, 1);
    rs_server_set_tries (server, 3);
    if (rs_server_set_secret (server, SECRET))
      return rs_err_conn_pop (conn);
  }
#else
  if (rs_context_read_config (h, av1))
    return rs_err_ctx_pop (h);
  if (rs_conn_create (h, &conn, av2))
    return rs_err_conn_pop (conn);
#endif	/* USE_CONFIG_FILE */

  if (rs_packet_create_acc_request (conn, &req, USER_NAME, USER_PW))
    return rs_err_conn_pop (conn);

#if !defined(USE_REQUEST_OBJECT)
  if (rs_packet_send (req, NULL))
    return rs_err_conn_pop (conn);
  req = NULL;
  if (rs_conn_receive_packet (conn, &resp))
    return rs_err_conn_pop (conn);
#else
  {
    struct rs_request *request;

    if (rs_request_new (conn, &request))
      return rs_err_conn_pop (conn);
    if (rs_req_send (request, req, &resp))
      return rs_err_conn_pop (conn);
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

  err = blocking_client (argv[1], argv[2]);
  if (err)
    {
      fprintf (stderr, "%s\n", rs_err_msg (err, 0));
      return rs_err_code (err, 1);
    }
  return 0;
}
