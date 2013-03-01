/* RADIUS/RadSec client using libradsec in blocking mode. */

/* Copyright 2010,2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <radsec/radsec.h>
#include <radsec/request.h>
#include "err.h"
#include "debug.h"		/* For rs_dump_message().  */

#define SECRET "sikrit"
#define USER_NAME "molgan@PROJECT-MOONSHOT.ORG"
#define USER_PW "password"

struct rs_error *
blocking_client (const char *av1, const char *av2, const char *av3,
                 int use_request_object_flag)
{
  struct rs_context *h = NULL;
  struct rs_connection *conn = NULL;
  struct rs_request *request = NULL;
  struct rs_message *req = NULL, *resp = NULL;
  struct rs_error *err = NULL;
  int r;
#if defined (USE_CONFIG_FILE)
  const char *config_fn= av1;
  const char *configuration = av2;
#else
  const char *host = av1;
  const char *service = av2;
  const char *proto = av3;
  struct rs_peer *server;
#endif

  r = rs_context_create (&h);
  if (r)
    {
      assert(r == RSE_NOMEM);
      assert (!"out of RAM -- unable to create libradsec context");
    }

#if !defined (USE_CONFIG_FILE)
  /* Do it without a configuration file by setting all stuff "by
   hand".  Doesn't work for TLS at the moment because we don't have an
   API for setting the X509 cert file names and such. */
  {
    int conn_type = RS_CONN_TYPE_UDP;

    if (rs_conn_create (h, &conn, NULL))
      goto cleanup;
    if (proto)
      {
        if (!strncmp (proto, "udp", strlen ("udp")))
          conn_type = RS_CONN_TYPE_UDP;
        else if (!strncmp (proto, "tls", strlen ("tls")))
          conn_type = RS_CONN_TYPE_TLS;
      }
    rs_conn_set_type (conn, conn_type);
    if (rs_peer_create_for_conn (conn, &server))
      goto cleanup;
    if (rs_peer_set_address (server, host, service))
      goto cleanup;
    rs_peer_set_timeout (server, 1);
    rs_peer_set_retries (server, 3);
    if (rs_peer_set_secret (server, SECRET))
      goto cleanup;
  }
#else  /* defined (USE_CONFIG_FILE) */
  if (rs_context_read_config (h, config_fn))
    goto cleanup;
  if (rs_conn_create (h, &conn, configuration))
    goto cleanup;
#endif	/* defined (USE_CONFIG_FILE) */

  if (use_request_object_flag)
    {
      if (rs_request_create_authn (conn, &request, USER_NAME, USER_PW, SECRET))
	goto cleanup;
      if (rs_request_send (request, &resp))
	goto cleanup;
    }
  else
    {
      if (rs_message_create_authn_request (conn, &req, USER_NAME, USER_PW, SECRET))
	goto cleanup;
      if (rs_message_send (req, NULL))
	goto cleanup;
      if (rs_conn_receive_message (conn, req, &resp))
	goto cleanup;
    }

  if (resp)
    {
      rs_dump_message (resp);
      if (rs_message_code (resp) == PW_ACCESS_ACCEPT)
	printf ("Good auth.\n");
      else
	printf ("Bad auth: %d\n", rs_message_code (resp));
    }
  else
    fprintf (stderr, "%s: no response\n", __func__);

 cleanup:
  err = rs_err_ctx_pop (h);
  if (err == RSE_OK)
    err = rs_err_conn_pop (conn);
#if !defined (USE_CONFIG_FILE)
  rs_peer_free_address (server);
  rs_peer_free_secret (server);
#endif
  if (resp)
    rs_message_destroy (resp);
  if (request)
    rs_request_destroy (request);
  if (conn)
    rs_conn_destroy (conn);
  if (h)
    rs_context_destroy (h);

  return err;
}

void
usage (int argc, char *argv[])
{
  fprintf (stderr, "usage: %s: [-r] config-file config-name\n", argv[0]);
  exit (1);
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
  if (argc < 3)
    usage (argc, argv);
  err = blocking_client (argv[1], argv[2], argc >= 3 ? argv[3] : NULL,
                         use_request_object_flag);
  if (err)
    {
      fprintf (stderr, "error: %s: %d\n", rs_err_msg (err), rs_err_code (err, 0));
      return rs_err_code (err, 1);
    }
  return 0;
}
