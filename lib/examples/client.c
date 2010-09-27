/* RADIUS client doing blocking i/o.  */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../libradsec.h"
#include "../debug.h"

#define SECRET "sikrit"
#define USER_NAME "bob"
#define USER_PW "hemligt"

int
rsx_client (const char *srvname, int srvport)
{
  struct rs_context *h;
  struct rs_connecion *conn;
  struct rs_packet *req, *resp;

  if (rs_context_create (&h, "/usr/share/freeradius/dictionary"))
    return rs_err_code (rs_ctx_err_code (h));

  if (rs_conn_new (h, &conn))
    return rs_err_code (rs_conn_err_code (conn));
  if (rs_conn_add_server (conn, RS_CONN_TYPE_UDP, srvname, srvport, 10, 3, SECRET))
    return rs_err_code (rs_conn_err_code (conn));

  if (rs_packet_create_acc_request (conn, &req, USER_NAME, USER_PW))
    return rs_err_code (rs_conn_err_code (conn));

  if (rs_packet_send (req))
    return rs_err_code (rs_conn_err_code (conn));
  req = NULL;

  if (rs_packet_recv (conn, &resp))
    return rs_err_code (rs_conn_err_code (conn));

  rs_conn_destroy (conn);
  rs_context_destroy (h);
}

int
main (int argc, char *argv[])
{
  exit (rsx_client ());
}
