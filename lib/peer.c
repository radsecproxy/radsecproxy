/* See the file COPYING for licensing information.  */
#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

int
rs_peer_create (struct rs_connection *conn, struct rs_peer **peer_out)
{
  struct rs_peer *peer;

  peer = _rs_peer_create (conn->ctx, &conn->peers);
  if (peer)
    {
      peer->conn = conn;
      peer->realm->timeout = 2;
      peer->realm->retries = 2;
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
  struct rs_error *err;

  assert (peer);
  assert (peer->realm);

  err = _rs_resolv (&peer->addr, peer->realm->type, hostname, service);
  if (err)
    return _rs_err_conn_push_err (peer->conn, err);
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

