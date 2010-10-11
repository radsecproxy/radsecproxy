/* See the file COPYING for licensing information.  */

struct rs_request
{
  struct rs_connection *conn;
  struct event *timer;
  struct rs_packet *req;
  struct rs_packet *resp;
  struct rs_conn_callbacks saved_cb;
  int verified;
};

#define VENDORPEC_MS                        311 /* RFC 2548 */

#define PW_MS_MPPE_SEND_KEY                 16
#define PW_MS_MPPE_RECV_KEY                 17
