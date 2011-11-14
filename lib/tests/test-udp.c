#include <stdlib.h>
#include <cgreen/cgreen.h>
#include "radsec/radsec.h"
#include "radsec/request.h"
#include "udp.h"

#define true 1			/* FIXME: Bug report cgreen.  */
#define false 0

static void
authenticate (struct rs_connection *conn, const char *user, const char *pw)
{
  struct rs_request *req;
  struct rs_packet *msg, *resp;

  assert_true (rs_request_create (conn, &req) == 0);
  assert_true (rs_packet_create_authn_request (conn, &msg, user, pw) == 0);
  rs_request_add_reqpkt (req, msg);
  assert_true (rs_request_send (req, &resp) == 0);
  //printf ("%s\n", rs_err_msg (rs_err_conn_pop (conn), 1));
  assert_true (rs_packet_code(resp) == PW_ACCESS_ACCEPT);

  rs_request_destroy (req);
}

static void
send_more_than_one_msg_in_one_packet (struct rs_connection *conn)
{
  struct rs_packet *msg0, *msg1;

  assert_true (rs_packet_create_authn_request (conn, &msg0, NULL, NULL) == 0);
  assert_true (rs_packet_create_authn_request (conn, &msg1, NULL, NULL) == 0);
  assert_true (rs_packet_send (msg0, NULL) == 0);
  assert_true (rs_packet_send (msg1, NULL) == 0);
}

static void
send_large_packet (struct rs_connection *conn)
{
  struct rs_packet *msg0;
  struct rs_attr *attr_x;
  char *buf;
  int f;

  buf = malloc (RS_MAX_PACKET_LEN);
  assert_true (buf != NULL);
  memset (buf, 0, RS_MAX_PACKET_LEN);

  assert_true (rs_packet_create (conn, &msg0) == 0);
  /* 16 chunks --> heap corruption in evbuffer_drain detected by free() */
  for (f = 0; f < 15; f++)
    {
      memset (buf, 'a' + f, 252);
      rs_attr_create (conn, &attr_x, "EAP-Message", buf);
      rs_packet_add_attr (msg0, attr_x);
    }
  assert_true (rs_packet_send (msg0, NULL) == 0);
}

/* ************************************************************ */
static struct setup {
  char *config_file;
  char *config_name;
  char *username;
  char *pw;
} setup;

static void
test_auth ()
{
  struct rs_context *ctx;
  struct rs_connection *conn;

  setup.config_file = "test.conf";
  setup.config_name = "test-udp-auth";
  setup.username = "molgan";
  setup.pw = "password";

  assert_true (rs_context_create (&ctx, NULL) == 0);
  assert_true (rs_context_read_config (ctx, setup.config_file) == 0);
  assert_true (rs_conn_create (ctx, &conn, setup.config_name) == 0);

  authenticate (conn, setup.username, setup.pw);

  rs_conn_destroy (conn);
  rs_context_destroy (ctx);
}

static ssize_t
test_buffering_cb (const uint8_t *buf, ssize_t len)
{
  /* "Exactly one RADIUS packet is encapsulated in the UDP Data field"
     [RFC 2865]*/
#if 0
  hd (buf, len);
#endif
  assert_true (len >= 20);
  assert_true (len <= RS_MAX_PACKET_LEN);
  assert_true ((buf[2] << 8) +  buf[3] == len);
  return len;
}

static void
test_buffering ()
{
  struct rs_context *ctx;
  struct rs_connection *conn;
  struct timeval timeout;
  struct polldata *polldata;

  assert_true (rs_context_create (&ctx, NULL) == 0);
  assert_true (rs_context_read_config (ctx, "test.conf") == 0);
  assert_true (rs_conn_create (ctx, &conn, "test-udp-buffering") == 0);

  timeout.tv_sec = 0;
  timeout.tv_usec = 150000;
  polldata = udp_server ("11820", &timeout, test_buffering_cb);
  assert_true (polldata != NULL);

  send_more_than_one_msg_in_one_packet (conn);
  assert_true (udp_poll (polldata) > 0);
  assert_true (udp_poll (polldata) > 0);

  send_large_packet (conn);
  assert_true (udp_poll (polldata) > 0);

  udp_free_polldata (polldata);
  rs_conn_destroy (conn);
  rs_context_destroy (ctx);
}

/* ************************************************************ */
static void
setup_auth (TestSuite *ts)
{
  add_test (ts, test_auth);
}

static void
setup_buffering (TestSuite *ts)
{
  add_test (ts, test_buffering);
}

int
main (int argc, char *argv[])
{
  TestSuite *ts = create_test_suite ();

  setup_auth (ts);
  setup_buffering (ts);

  if (argc > 1)
    return run_single_test (ts, argv[1], create_text_reporter ());
  else
    return run_test_suite (ts, create_text_reporter ());
}
