/* RADIUS client doing blocking i/o.  */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <event2/event.h>
#include <freeradius/libradius.h>
#include <radsec/radsec.h>
#include <radsec/request.h>

#define SECRET "sikrit"
#define USER_NAME "molgan"
#define USER_PW "password"

struct rs_error *
blocking_client (const char *av1, const char *av2, int use_request_object_flag)
{
  struct rs_context *h;
  struct rs_connection *conn;
  struct rs_packet *req, *resp = NULL;

  if (rs_context_create (&h, "/usr/share/freeradius/dictionary"))
    return NULL;

#if !defined (USE_CONFIG_FILE)
  {
    struct rs_peer *server;

    if (rs_conn_create (h, &conn, NULL))
      return rs_err_conn_pop (conn);
    rs_conn_set_type (conn, RS_CONN_TYPE_UDP);
    if (rs_peer_create (conn, &server))
      return rs_err_conn_pop (conn);
    if (rs_peer_set_address (server, av1, av2))
      return rs_err_conn_pop (conn);
    rs_peer_set_timeout (server, 1);
    rs_peer_set_retries (server, 3);
    if (rs_peer_set_secret (server, SECRET))
      return rs_err_conn_pop (conn);
  }
#else
  if (rs_context_read_config (h, av1))
    return rs_err_ctx_pop (h);
  if (rs_conn_create (h, &conn, av2))
    return rs_err_conn_pop (conn);
#endif	/* USE_CONFIG_FILE */

  if (use_request_object_flag)
    {
      struct rs_request *request;

      if (rs_request_create (conn, &request, USER_NAME, USER_PW))
	return rs_err_conn_pop (conn);
      if (rs_request_send (request, &resp))
	return rs_err_conn_pop (conn);
      rs_request_destroy (request);
    }
  else
    {
      if (rs_packet_create_auth_request (conn, &req, USER_NAME, USER_PW))
	return rs_err_conn_pop (conn);

      if (rs_packet_send (req, NULL))
	{
	  rs_packet_destroy (req);
	  return rs_err_conn_pop (conn);
	}
      if (rs_conn_receive_packet (conn, req, &resp))
	{
	  rs_packet_destroy (req);
	  return rs_err_conn_pop (conn);
	}
      rs_packet_destroy (req);
    }

  if (resp)
    {
      RADIUS_PACKET *fr_pkt = NULL;
      VALUE_PAIR *fr_vp = NULL;

      fr_pkt = rs_packet_frpkt (resp);
      fr_vp = fr_pkt->vps;	/* FIXME: Is there an accessor?  */
      if (fr_vp)
	vp_printlist(stdout, fr_vp);
      rs_packet_destroy (resp);
    }

  rs_conn_destroy (conn);
  rs_context_destroy (h);
  return NULL;
}

int
main (int argc, char *argv[])
{
  int use_request_object_flag = 0;
  struct rs_error *err;

  if (argc > 1 && argv[1] && argv[1][0] == '-' && argv[1][1] == 'r')
    {
      use_request_object_flag = 1;
      argc--;
      argv++;
    }
  err = blocking_client (argv[1], argv[2], use_request_object_flag);
  if (err)
    {
      fprintf (stderr, "%s\n", rs_err_msg (err, 0));
      return rs_err_code (err, 1);
    }
  return 0;
}
