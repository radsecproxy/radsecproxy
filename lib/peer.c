/* Copyright 2010-2012 NORDUnet A/S. All rights reserved.
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
  if (!conn->active_peer)
    conn->active_peer = conn->peers; /* From the top.  */

  return conn->active_peer;
}

struct rs_peer *
peer_create (struct rs_context *ctx, struct rs_peer **rootp)
{
  struct rs_peer *p;

  p = (struct rs_peer *) rs_malloc (ctx, sizeof(*p));
  if (p)
    {
      memset (p, 0, sizeof(struct rs_peer));
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

/* Public functions.  */
int
rs_peer_create (struct rs_connection *conn, struct rs_peer **peer_out)
{
  struct rs_peer *peer;

  peer = peer_create (conn->ctx, &conn->peers);
  if (peer)
    {
      peer->conn = conn;
      peer->realm->timeout = 2;	/* FIXME: Why?  */
      peer->realm->retries = 2;	/* FIXME: Why?  */
    }
  else
    return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
  if (*peer_out)
    *peer_out = peer;
  return RSE_OK;
}

int
rs_peer_set_address (struct rs_peer *peer, const char *hostname,
                     const char *service)
{
  assert (peer);
  assert (peer->conn);
  assert (peer->conn->ctx);

  peer->hostname = rs_strdup (peer->conn->ctx, hostname);
  peer->service = rs_strdup (peer->conn->ctx, service);
  if (peer->hostname == NULL || peer->service == NULL)
    return RSE_NOMEM;

  return RSE_OK;
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
  if (peer->secret)
    free (peer->secret);
  peer->secret = (char *) malloc (strlen(secret) + 1);
  if (!peer->secret)
    return rs_err_conn_push (peer->conn, RSE_NOMEM, NULL);
  strcpy (peer->secret, secret);
  return RSE_OK;
}

