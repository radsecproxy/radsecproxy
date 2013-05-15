/* Copyright 2011,2013, NORDUnet A/S. All rights reserved. */
/* See LICENSE for licensing information. */

#include <stdlib.h>
#include <assert.h>
#include <CUnit/Basic.h>
#include "radius/client.h"
#include "radsec/radsec.h"
#include "radsec/request.h"
#include "udp.h"

static void
authenticate (struct rs_connection *conn, const char *user, const char *pw)
{
  struct rs_request *req;
  struct rs_packet *msg, *resp;

  CU_ASSERT (rs_request_create (conn, &req) == 0);
  CU_ASSERT (!rs_packet_create_authn_request (conn, &msg, user, pw));
  rs_request_add_reqpkt (req, msg);
  CU_ASSERT (rs_request_send (req, &resp) == 0);
  //printf ("%s\n", rs_err_msg (rs_err_conn_pop (conn), 1));
  CU_ASSERT (rs_packet_code(resp) == PW_ACCESS_ACCEPT);

  rs_request_destroy (req);
}

static void
send_more_than_one_msg_in_one_packet (struct rs_connection *conn)
{
  struct rs_packet *msg0, *msg1;

  CU_ASSERT (rs_packet_create_authn_request (conn, &msg0, NULL, NULL) == 0);
  CU_ASSERT (rs_packet_create_authn_request (conn, &msg1, NULL, NULL) == 0);
  CU_ASSERT (rs_packet_send (msg0, NULL) == 0);
  CU_ASSERT (rs_packet_send (msg1, NULL) == 0);
}

#if 0
static void
send_large_packet (struct rs_connection *conn)
{
  struct rs_packet *msg0;
  struct radius_packet *frpkt = NULL;
  char *buf;
  int f;

  buf = malloc (RS_MAX_PACKET_LEN);
  CU_ASSERT (buf != NULL);
  memset (buf, 0, RS_MAX_PACKET_LEN);

  CU_ASSERT (rs_packet_create (conn, &msg0) == 0);
  /* 16 chunks --> heap corruption in evbuffer_drain detected by free() */
  for (f = 0; f < 15; f++)
    {
      memset (buf, 'a' + f, 252);
      //vp = pairmake ("EAP-Message", buf, T_OP_EQ);
      CU_ASSERT (rs_packet_append_avp (msg0, fixme...) == RSE_OK);
    }
  CU_ASSERT (rs_packet_send (msg0, NULL) == 0);
}
#endif  /* 0 */

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
  setup.username = "molgan@PROJECT-MOONSHOT.ORG";
  setup.pw = "password";

  CU_ASSERT (rs_context_create (&ctx) == 0);
  CU_ASSERT (rs_context_read_config (ctx, setup.config_file) == 0);
  CU_ASSERT (rs_conn_create (ctx, &conn, setup.config_name) == 0);

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
  CU_ASSERT (len >= 20);
  CU_ASSERT (len <= RS_MAX_PACKET_LEN);
  CU_ASSERT ((buf[2] << 8) +  buf[3] == len);
  return len;
}

static void
test_buffering ()
{
  struct rs_context *ctx;
  struct rs_connection *conn;
  struct timeval timeout;
  struct polldata *polldata;

  CU_ASSERT (rs_context_create (&ctx) == 0);
  CU_ASSERT (rs_context_read_config (ctx, "test.conf") == 0);
  CU_ASSERT (rs_conn_create (ctx, &conn, "test-udp-buffering") == 0);

  timeout.tv_sec = 0;
  timeout.tv_usec = 150000;
  polldata = udp_server ("11820", &timeout, test_buffering_cb);
  CU_ASSERT (polldata != NULL);

  send_more_than_one_msg_in_one_packet (conn);
  CU_ASSERT (udp_poll (polldata) > 0);
  CU_ASSERT (udp_poll (polldata) > 0);


  udp_free_polldata (polldata);
  rs_conn_destroy (conn);
  rs_context_destroy (ctx);
}

/* ************************************************************ */
int
main (int argc, char *argv[])
{
  CU_pSuite s = NULL;
  CU_pTest t = NULL;
  unsigned int nfail;

  assert (CU_initialize_registry () == CUE_SUCCESS);
  s =  CU_add_suite ("auth", NULL, NULL); assert (s);
  t = CU_ADD_TEST (s, test_auth); assert (t);
  s =  CU_add_suite ("buffering", NULL, NULL); assert (s);
  t = CU_ADD_TEST (s, test_buffering); assert (t);

  assert (CU_basic_run_tests () == CUE_SUCCESS);
  nfail = CU_get_number_of_failures();

  CU_cleanup_registry ();
  return nfail;
}
