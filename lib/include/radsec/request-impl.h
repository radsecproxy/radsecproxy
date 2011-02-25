/* See the file COPYING for licensing information.  */

#if defined (__cplusplus)
extern "C" {
#endif

struct rs_request
{
  struct rs_connection *conn;
  struct event *timer;
  struct rs_packet *req_msg;
  struct rs_packet *resp_msg;
  struct rs_conn_callbacks saved_cb;
};

#if defined (__cplusplus)
}
#endif
