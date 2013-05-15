/* Copyright 2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <assert.h>
#include <event2/listener.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "listener.h"
#include "conn.h"
#include "peer.h"
#include "event.h"
#include "debug.h"

struct rs_listener *
listener_create (struct rs_context *ctx, struct rs_listener **rootp)
{
  struct rs_listener *listener;

  listener = rs_calloc (ctx, 1, sizeof (*listener));
  if (listener)
    {
      if (*rootp == NULL)
        *rootp = listener;
      else
        {
          listener->next = (*rootp)->next;
          (*rootp)->next = listener;
        }
    }
  return listener;
}

void
listener_accept_cb_ (struct evconnlistener *evconnlistener,
                     evutil_socket_t newfd,
                     struct sockaddr *srcaddr_sa,
                     int srcaddr_len,
                     void *user_data)
{
  int err = RSE_OK;
  struct rs_listener *l = NULL;
  struct rs_connection *newconn = NULL;
  struct rs_context *ctx = NULL;
  struct rs_peer *clients = NULL;

  l = (struct rs_listener *) user_data;
  assert (l);
  assert (l->base_.magic == RS_CONN_MAGIC_LISTENER);
  assert (l->evlistener == evconnlistener);
  ctx = l->base_.ctx;
  assert (ctx);

#if defined (DEBUG)
  {
    char host[80], port[80];
    getnameinfo (srcaddr_sa, srcaddr_len, host, sizeof(host),
                 port, sizeof(port), 0);
    rs_debug (("%s: incoming connection from %s:%s\n", __func__, host, port));
  }
#endif

/*
Application needs to specify acceptable clients -- we need to verify
src addr in the UDP case and x509 client cert in the TLS case. A list
of peers with proper pointers to realms should be a good way of doing
this.

Ask the application for a list of acceptable clients. Default to
accepting any potential configured client block in the realm of the
listener.  Note that this for this to be an opption, the application
must have read a config file. If there is no configuration, reject the
client.
*/
  if (l->callbacks.client_filter_cb)
    clients = l->callbacks.client_filter_cb (l, TO_BASE_CONN(l)->user_data);
  if (clients == NULL)
    clients = connbase_get_peers (TO_BASE_CONN(l));
  if (clients == NULL)
    {
      rs_debug (("%s: didn't get a client list for listener %p\n",
                 __func__, l));
      return;
    }
  rs_debug (("%s: using client list %p\n", __func__, clients));

  err = rs_conn_create (ctx, &newconn, NULL);
  if (err)
    {
      rs_debug (("%s: failed creating a new struct rs_connection: %d\n",
                __func__, err));
      return;                /* FIXME: Verify that this is handled. */
    }

  assert(clients);
  /* TODO: Picking the very first peer is not really what we want to
     do. For UDP, we can look at src ip and try to find a matching
     peer. For TLS, it's worse because we don't have the certificate
     until we've accepted the TCP connection. */
  TO_BASE_CONN(newconn)->realm = clients->realm;
  newconn->active_peer = clients;

  TO_BASE_CONN(newconn)->fd = newfd;
  TO_BASE_CONN(newconn)->transport = TO_BASE_CONN(l)->realm->type;
  err = event_init_bufferevent (newconn);
  if (err)
    {
      rs_debug (("%s: failed init bev: %d\n", __func__, err));
      goto errout;
    }

  /* Create a message and set up a read event. This installs the
     callback performing the TLS verification. */
  {                             /* FIXME */
    struct rs_message *msg = NULL;
    err = rs_message_create (newconn, &msg);
    if (err)
      abort ();                 /* FIXME */
    conn_add_read_event (newconn, msg);
  }

  if (l->callbacks.new_conn_cb)
    l->callbacks.new_conn_cb (newconn, TO_BASE_CONN(l)->user_data);
  return;                       /* Success. */

 errout:
  rs_conn_destroy (newconn);
  if (l->callbacks.error_cb)
    l->callbacks.error_cb (newconn, TO_BASE_CONN(l)->user_data);
}

void
listener_err_cb_ (struct evconnlistener *listener, void *user_data)
{
  rs_debug (("%s: FIXME: handle error\n", __func__));
}

/* Public functions. */
int
rs_listener_create (struct rs_context *ctx,
                    struct rs_listener **listener_out,
                    const char *config)
{
  int err = RSE_OK;
  struct rs_listener *listener = NULL;

  assert (ctx);

  listener = rs_calloc (ctx, 1, sizeof (*listener));
  if (listener == NULL)
    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);
  conn_init (ctx, TO_BASE_CONN (listener), RS_CONN_OBJTYPE_LISTENER);
  err = conn_configure (ctx, TO_BASE_CONN (listener), config);
  if (err)
    goto errout;

  if (listener_out)
    *listener_out = listener;
  return RSE_OK;

 errout:
  if (listener)
    rs_free (ctx, listener);
  return err;
}

void
rs_listener_set_callbacks (struct rs_listener *listener,
                           const struct rs_listener_callbacks *cb,
                           void *user_data)
{
  assert (listener);
  TO_BASE_CONN(listener)->user_data = user_data;
  memcpy (&listener->callbacks, cb, sizeof (listener->callbacks));
}

int
rs_listener_listen (struct rs_listener *listener)
{
  int err = RSE_OK;
  struct rs_conn_base *connbase = NULL;
  assert (listener);
  connbase = TO_BASE_CONN (listener);

  err = event_init_eventbase (connbase);
  if (err)
    return err;
  err = event_init_socket (connbase, connbase->realm->local_addr);
  if (err)
    return err;
#if 0
  {
    struct linger l;
    l.l_onoff = 1;
    l.l_linger = 0;
    rs_debug (("%s: setting SO_LINGER 0s on fd %d\n", __func__, connbase->fd));
    assert (0 == setsockopt (connbase->fd, SOL_SOCKET, SO_LINGER,
                             (void*)&l, sizeof(l)));
  }
#endif
  return err;
}

int
rs_listener_dispatch (const struct rs_listener *listener)
{
  assert (listener);
  assert (TO_BASE_CONN(listener)->ctx);
  return event_base_dispatch (TO_BASE_CONN(listener)->ctx->evb);
}

int
rs_listener_close (struct rs_listener *l)
{
  int err = baseconn_close (TO_BASE_CONN (l));
  return err;
}

struct event_base *
rs_listener_get_eventbase (const struct rs_listener *l)
{
  assert (TO_BASE_CONN (l));
  assert (TO_BASE_CONN (l)->ctx);
  return TO_BASE_CONN (l)->ctx->evb;
}

int
rs_listener_get_fd (const struct rs_listener *l)
{
  assert (TO_BASE_CONN (l));
  return TO_BASE_CONN (l)->fd;
}
