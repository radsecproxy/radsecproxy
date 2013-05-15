/* RADIUS/RadSec client using libradsec in user dispatch mode. */

#include <stdio.h>
#include <string.h>
#include <radsec/radsec.h>
#include <event2/event.h>
#include "debug.h"		/* For rs_dump_packet().  */

#define CONFIG "dispatching-tls"
#define CONFIG_FILE "examples/client.conf"

#define SECRET "sikrit"
#define USER_NAME "molgan@PROJECT-MOONSHOT.ORG"
#define USER_PW "password"

struct state {
  struct rs_packet *msg;
  unsigned packet_sent_flag : 1;
  unsigned packet_received_flag : 1;
};

static void
connected_cb (void *user_data)
{
  printf ("%s\n", __FUNCTION__);
}

static void
disconnected_cb (void *user_data)
{
  printf ("%s\n", __FUNCTION__);
}

static void
msg_received_cb (struct rs_packet *packet, void *user_data)
{
  struct state *state = (struct state *) user_data;

  printf ("%s\n", __FUNCTION__);

  state->msg = packet;
  state->packet_received_flag = 1;
}

static void
msg_sent_cb (void *user_data)
{
  struct state *state = (struct state *) user_data;

  printf ("%s\n", __FUNCTION__);

  rs_packet_destroy (state->msg);
  state->packet_sent_flag = 1;
}

struct rs_error *
dispatching_client (struct rs_context *ctx)
{
  struct rs_connection *conn = NULL;
  struct rs_conn_callbacks cb = { connected_cb, disconnected_cb,
                                  msg_received_cb, msg_sent_cb };
  struct rs_packet *req_msg = NULL;
  struct rs_error *err = NULL;
  struct state state;

  memset (&state, 0, sizeof (state));

  if (rs_conn_create(ctx, &conn, CONFIG))
    goto out;
  rs_conn_set_callbacks (conn, &cb, &state);
  if (rs_packet_create_authn_request (conn, &req_msg, USER_NAME, USER_PW))
    goto out;
  /* Doesn't really send the message but rather queues it for sending.
     msg_received_cb() will be invoked with user_data = &state when
     the message has been sent.  */
  if (rs_packet_send (req_msg))
    goto out;

  while (1)
    {
      if (rs_conn_dispatch (conn))
        goto out;
      if (state.packet_received_flag)
        {
          rs_dump_packet (state.msg); /* debug printout */
          if (rs_packet_code (state.msg) == PW_ACCESS_ACCEPT)
            printf ("Good auth.\n");
          else
            printf ("Bad auth: %d\n", rs_packet_code (state.msg));
          rs_packet_destroy (state.msg);
          break;
        }
    }

  if (rs_conn_destroy(conn))
    goto out;
  conn = NULL;

 out:
  err = rs_err_ctx_pop (ctx);
  if (err == RSE_OK)
    err = rs_err_conn_pop (conn);

  if (conn)
    rs_conn_destroy(conn);

  return err;
}

int
main (int argc, char *argv[])
{
  struct rs_error *err = NULL;
  struct rs_context *ctx = NULL;

  if (rs_context_create(&ctx))
    goto out;
  if (rs_context_read_config(ctx, CONFIG_FILE))
    goto out;

  err = dispatching_client (ctx);

 out:
  if (ctx)
    rs_context_destroy(ctx);

  if (err)
    {
      fprintf (stderr, "error: %s: %d\n", rs_err_msg (err), rs_err_code (err, 0));
      return rs_err_code (err, 1);
    }
  return 0;
}
