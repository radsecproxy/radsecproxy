/* RADIUS/RadSec server using libradsec. */

/* Copyright 2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <radsec/radsec.h>
#include <event2/event.h>
#include "debug.h"		/* For rs_dump_message(). */

#define CONFIG_FILE "examples/server.conf"
#define CONFIG "tls"

#define SECRET "sikrit"
#define USER_NAME "molgan@PROJECT-MOONSHOT.ORG"
#define USER_PW "password"

static struct rs_peer *
client_filter_cb (const struct rs_listener *listener,
                  void *user_data)
{
  printf ("DEBUG: listener %p (user_data=%p) asking for a client filter list\n",
          listener, user_data);
  return NULL;
}

static void
disco_cb (void *user_data)
{
  struct rs_connection *conn = user_data;
  assert (conn);
  printf ("DEBUG: conn %p disconnected\n", conn);
}

static void
read_cb (struct rs_message *message, void *user_data)
{
  struct rs_connection *conn = user_data;
  assert (conn);
  printf ("DEBUG: msg received on connection %p\n", conn);
  rs_dump_message (message);
  //if (message_verify_response (conn, fixme)) error;
}

static void
new_conn_cb (struct rs_connection *conn, void *user_data)
{
  const struct rs_listener *l = user_data;
  struct rs_conn_callbacks cb = {NULL, /* connected */
                                 disco_cb,
                                 read_cb,
                                 NULL}; /* msg sent */

  printf ("DEBUG: new connection on listener %p: %p, fd=%d\n",
          l, conn, rs_conn_get_fd (conn));
  rs_conn_set_callbacks (conn, &cb, conn);
}

void
err_cb (struct rs_connection *conn, void *user_data)
{
  struct rs_listener *listener = user_data;
  struct rs_error *err = NULL;
  assert (conn);
  err = rs_err_conn_pop (conn);

  printf ("DEBUG: error on conn %p, listener %p: %d (%s)\n", conn, listener,
          rs_err_code (err, 0), rs_err_msg (err));
}

#if 0
void
stdin_cb (evutil_socket_t s, short flags, void *user_data)
{
  struct rs_listener *l = user_data;

  printf ("DEBUG: got data on stdin, quitting\n");
  assert (event_base_loopbreak (rs_listener_get_eventbase (l)) == 0);
}
#endif

struct rs_error *
server (struct rs_context *ctx)
{
  int r = 0;
  struct rs_error *err = NULL;
  struct rs_listener *listener = NULL;
  const struct rs_listener_callbacks cbs =
    {client_filter_cb, new_conn_cb, err_cb};
  struct event *read_event = NULL;

  if (rs_listener_create (ctx, &listener, CONFIG))
    goto out;
  rs_listener_set_callbacks (listener, &cbs, listener);
  if (rs_listener_listen (listener))
    goto out;

#if 0
  /* Listen on stdin too, for quitting the server nicely without
     having to trap SIGKILL. */
  read_event = event_new (rs_listener_get_eventbase (listener),
                          fileno (stdin),
                          EV_READ,
                          stdin_cb,
                          listener);
  assert (read_event != NULL);
  assert (event_add (read_event, NULL) == 0);
#endif

  do
    r = rs_listener_dispatch (listener);
  while (r == 0);

  printf ("DEBUG: rs_listener_dispatch done (r=%d)\n", r);
  if (r < 0)
    printf ("DEBUG: libevent signals error: %s\n", evutil_gai_strerror (r));
  if (r == 1)
    printf ("DEBUG: no events registered, exiting\n");

 out:
  err = rs_err_ctx_pop (ctx);
  if (err == NULL)
    err = rs_err_listener_pop (listener);

  if (read_event)
    event_free (read_event);
  read_event = NULL;
  if (listener)
    {
      assert (rs_listener_close (listener) == RSE_OK);
      //rs_listener_destroy (listener);
    }
  listener = NULL;

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
  if (err)
    {
      fprintf (stderr, "%s: error: %s: %d\n",
               argv[0], rs_err_msg (err), rs_err_code (err, 0));
      return rs_err_code (err, 1);
    }

  if (ctx)
    rs_context_destroy (ctx);

  return 0;
}
