/* Copyright 2010,2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "err.h"
#include "peer.h"
#include "util.h"

struct rs_peer *
peer_pick_peer (struct rs_connection *conn)
{
  assert (conn);

  if (conn->active_peer)
    conn->active_peer = conn->active_peer->next; /* Next.  */
  if (conn->active_peer == NULL)
    conn->active_peer = TO_BASE_CONN (conn)->peers; /* From the top.  */

  return conn->active_peer;
}

struct rs_peer *
peer_create (struct rs_context *ctx, struct rs_peer **rootp)
{
  struct rs_peer *p;

  p = (struct rs_peer *) rs_calloc (ctx, 1, sizeof(*p));
  if (p)
    {
      if (*rootp)
	{
	  p->next = (*rootp)->next;
	  (*rootp)->next = p;
	}
      else
	*rootp = p;
    }
  return p;
}

int
peer_create_for_connbase (struct rs_conn_base *connbase,
                          struct rs_peer **peer_out)
{
  struct rs_peer *peer;

  peer = peer_create (connbase->ctx, &connbase->peers);
  if (peer == NULL)
    return rs_err_connbase_push_fl (connbase, RSE_NOMEM, __FILE__, __LINE__,
                                    NULL);
  peer->connbase = connbase;
  peer->realm = connbase->realm;

  if (*peer_out)
    *peer_out = peer;
  return RSE_OK;
}

/* Public functions.  */
int
rs_peer_create_for_conn (struct rs_connection *conn, struct rs_peer **peer_out)
{
  return peer_create_for_connbase (TO_BASE_CONN (conn), peer_out);
}

int
rs_peer_create_for_listener (struct rs_listener *listener,
                             struct rs_peer **peer_out)
{
  return peer_create_for_connbase (TO_BASE_CONN (listener), peer_out);
}

int
rs_peer_set_address (struct rs_peer *peer,
                     const char *hostname,
                     const char *service)
{
  assert (peer);
  assert (peer->connbase);
  assert (peer->connbase->ctx);

  peer->hostname = rs_strdup (peer->connbase->ctx, hostname);
  peer->service = rs_strdup (peer->connbase->ctx, service);
  if (peer->hostname == NULL || peer->service == NULL)
    return RSE_NOMEM;

  return RSE_OK;
}

void
rs_peer_free_address (struct rs_peer *peer)
{
  assert (peer);
  assert (peer->connbase);
  assert (peer->connbase->ctx);

  if (peer->hostname)
    rs_free (peer->connbase->ctx, peer->hostname);
  peer->hostname = NULL;
  if (peer->service)
    rs_free (peer->connbase->ctx, peer->service);
  peer->service = NULL;
}

void
rs_peer_set_timeout (struct rs_peer *peer, int timeout)
{
  assert (peer);
  assert (peer->realm);
  peer->realm->timeout = timeout;
}

void
rs_peer_set_retries (struct rs_peer *peer, int retries)
{
  assert (peer);
  assert (peer->realm);
  peer->realm->retries = retries;
}

int
rs_peer_set_secret (struct rs_peer *peer, const char *secret)
{
  assert (peer);
  assert (peer->connbase);
  assert (peer->connbase->ctx);

  rs_peer_free_secret (peer);
  peer->secret = rs_calloc (peer->connbase->ctx, 1, strlen(secret) + 1);
  if (!peer->secret)
    return rs_err_connbase_push (peer->connbase, RSE_NOMEM, NULL);
  strcpy (peer->secret, secret);
  return RSE_OK;
}

void
rs_peer_free_secret (struct rs_peer *peer)
{
  assert (peer);
  assert (peer->connbase);
  assert (peer->connbase->ctx);

  if (peer->secret)
    rs_free (peer->connbase->ctx, peer->secret);
  peer->secret = NULL;
}
