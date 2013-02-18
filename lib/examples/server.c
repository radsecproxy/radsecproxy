/* RADIUS/RadSec server using libradsec. */

/* Copyright 2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <radsec/radsec.h>
#include <event2/event.h>
#include "debug.h"		/* For rs_dump_message(). */

#define CONFIG_FILE "examples/test.conf"
#define CONFIG "tls"

#define SECRET "sikrit"
#define USER_NAME "molgan@PROJECT-MOONSHOT.ORG"
#define USER_PW "password"

void
new_conn_cb (struct rs_connection *conn, void *user_data)
{
  printf ("new connection: fd=%d\n", -1); /* conn->fd */
}

struct rs_error *
server (struct rs_context *ctx)
{
  int r = 0;
  struct rs_error *err = NULL;
  struct rs_connection *conn = NULL;
  struct rs_listener *listener = NULL;
  const struct rs_listener_callbacks cbs = {};

  if (rs_listener_create (ctx, &listener, CONFIG))
    goto out;
  rs_listener_set_callbacks (listener, &cbs);

  do
    {
      r = rs_listener_dispatch (listener);
      printf ("DEBUG: rs_listener_dispatch done (r=%d)\n", r);
    }
  while (r == 0);

 out:
  err = rs_err_ctx_pop (ctx);
  if (err == NULL)
    err = rs_err_conn_pop (conn);

#if 0
  if (listener)
    rs_listener_destroy (listener);
  listener = NULL;
#endif

  return err;
}

int
main (int argc, char *argv[])
{
  struct rs_error *err = NULL;
  struct rs_context *ctx = NULL;

  if (rs_context_create (&ctx))
    goto out;
  if (rs_context_read_config (ctx, CONFIG_FILE))
    goto out;

  {                             /* DEBUG printouts */
    char *buf = NULL;
    int err = rs_context_print_config (ctx, &buf);
    assert (err == RSE_OK);
    fputs (buf, stdout);
    free (buf);
  }

  err = server (ctx);

 out:
  if (ctx)
    rs_context_destroy (ctx);

  if (err)
    {
      fprintf (stderr, "error: %s: %d\n", rs_err_msg (err), rs_err_code (err, 0));
      return rs_err_code (err, 1);
    }
  return 0;
}
