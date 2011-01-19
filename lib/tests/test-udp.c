#include <stdlib.h>
#include <cgreen/cgreen.h>
#include <freeradius/libradius.h>
#include "radsec/radsec.h"
#include "radsec/request.h"

#define true 1			/* FIXME: Bug report cgreen.  */
#define false 0

#define FREERADIUS_DICT "/usr/share/freeradius/dictionary"

void
authenticate (struct rs_connection *conn, const char *user, const char *pw)
{
  struct rs_request *req;
  struct rs_packet *msg, *resp;

  assert_true (rs_request_create (conn, &req) == 0);
  assert_true (rs_packet_create_auth_request (conn, &msg, user, pw) == 0);
  assert_true (rs_request_send (req, msg, &resp) == 0);
  assert_true (rs_packet_frpkt (resp)->code == PW_AUTHENTICATION_ACK);

  rs_request_destroy(req);
}

#if 0
int
send_more_than_one_msg_in_one_packet (const char *server)
{
  struct rs_request *req;
  struct rs_packet *msg, *resp;



}
#endif

/* ************************************************************ */
static struct setup {
  char *config_file;
  char *config_name;
  char *username;
  char *pw;
} setup;

void
test_auth ()
{
  struct rs_context *ctx;
  struct rs_connection *conn;

  assert_true (rs_context_create (&ctx, FREERADIUS_DICT) == 0);
  assert_true (rs_context_read_config (ctx, setup.config_file) == 0);
  assert_true (rs_conn_create (ctx, &conn, setup.config_name) == 0);

  authenticate (conn, setup.username, setup.pw);

  rs_conn_destroy (conn);
  rs_context_destroy (ctx);
}

int
test_udp (int argc, char *argv[], TestSuite *ts)
{
  add_test (ts, test_auth);

  if (argc > 1)
    return run_single_test (ts, argv[1], create_text_reporter ());

  return run_test_suite (ts, create_text_reporter ());
}

int
main (int argc, char *argv[])
{
  TestSuite *ts = create_test_suite ();

  setup.config_file = "test.conf";
  setup.config_name = "test-udp";
  setup.username = "molgan";
  setup.pw = "password";

  return test_udp (argc, argv, ts);
}
