/* See the file COPYING for licensing information.  */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>

#include <freeradius/libradius.h>
#include <event2/event.h>
#include <event2/util.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

int
rs_context_create(struct rs_handle **ctx, const char *dict)
{
  struct rs_handle *h;

  if (ctx)
    *ctx = NULL;
  h = (struct rs_handle *) malloc (sizeof(struct rs_handle));
  if (h)
    {
      char *buf1 = NULL, *buf2 = NULL;
      char *dir, *fn;

      buf1 = malloc (strlen (dict) + 1);
      buf2 = malloc (strlen (dict) + 1);
      if (!buf1 || !buf2)
	{
	  free (h);
	  if (buf1)
	    free (buf1);
	  if (buf2)
	    free (buf2);
	  return RSE_NOMEM;
	}
      strcpy (buf1, dict);
      dir = dirname (buf1);
      strcpy (buf2, dict);
      fn = basename (buf2);
      if (dict_init (dir, fn) < 0)
	{
	  free (h);
	  return RSE_SOME_ERROR;
	}
      free (buf1);
      free (buf2);
#if defined (DEBUG)
      fr_log_fp = stderr;
      fr_debug_flag = 1;
#endif

      memset (h, 0, sizeof(struct rs_handle));
      fr_randinit (&h->fr_randctx, 0);
      fr_rand_seed (NULL, 0);

      if (ctx)
	*ctx = h;
    }
  return h ? RSE_OK : RSE_NOMEM;
}

void rs_context_destroy(struct rs_handle *ctx)
{
  free (ctx);
}

int rs_context_set_alloc_scheme(struct rs_handle *ctx, struct rs_alloc_scheme *scheme)
{
  return rs_err_ctx_push_fl (ctx, RSE_NOSYS, __FILE__, __LINE__,
			     "%s: NYI", __func__);
}

int rs_context_config_read(struct rs_handle *ctx, const char *config_file)
{
  return rs_err_ctx_push_fl (ctx, RSE_NOSYS, __FILE__, __LINE__,
			     "%s: NYI", __func__);
}

int
rs_conn_create(struct rs_handle *ctx, struct rs_connection **conn,
	       rs_conn_type_t type)
{
  struct rs_connection *c;

  c = (struct rs_connection *) malloc (sizeof(struct rs_connection));
  if (c)
    {
      memset (c, 0, sizeof(struct rs_connection));
      c->ctx = ctx;
      c->type = type;
    }
  if (conn)
    *conn = c;
  return c ? RSE_OK : rs_err_ctx_push (ctx, RSE_NOMEM, NULL);
}

struct addrinfo *
_resolv (struct rs_connection *conn, const char *hostname, int port)
{
  int err;
  char portstr[6];
  struct evutil_addrinfo hints, *res = NULL;

  snprintf (portstr, sizeof(portstr), "%d", port);
  memset (&hints, 0, sizeof(struct evutil_addrinfo));
  hints.ai_family = AF_UNSPEC;	/* v4 or v6.  */
  hints.ai_flags = AI_ADDRCONFIG;
  switch (conn->type)
    {
    case RS_CONN_TYPE_NONE:
      rs_err_conn_push_fl (conn, RSE_INVALID_CONN, __FILE__, __LINE__, NULL);
      return NULL;
    case RS_CONN_TYPE_TCP:
      /* Fall through.  */
    case RS_CONN_TYPE_TLS:
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      break;
    case RS_CONN_TYPE_UDP:
      /* Fall through.  */
    case RS_CONN_TYPE_DTLS:
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_protocol = IPPROTO_UDP;
      break;
    }
  err = evutil_getaddrinfo (hostname, portstr, &hints, &res);
  if (err)
    rs_err_conn_push_fl (conn, RSE_BADADDR, __FILE__, __LINE__,
			 "%s:%d: bad host name or port (%s)",
			 hostname, port, evutil_gai_strerror(err));
  return res;			/* Simply use first result.  */
}

static struct rs_peer *
_peer_new (struct rs_connection *conn)
{
  struct rs_peer *p;

  p = (struct rs_peer *) malloc (sizeof(*p));
  if (p)
    {
      memset (p, 0, sizeof(struct rs_peer));
      p->conn = conn;
      p->fd = -1;
      p->next = conn->peers;
      if (conn->peers)
	conn->peers->next = p;
      else
	conn->peers = p;
    }
  else
    rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
  return p;
}

int
rs_server_create (struct rs_connection *conn, struct rs_peer **server,
		  const char *config)
{
  struct rs_peer *srv;

  srv = _peer_new (conn);
  if (srv)
    {
      srv->timeout = 1;
      srv->tries = 3;
    }
  *server = srv;
  return srv ? RSE_OK : -1;
}

int
rs_server_set_address (struct rs_peer *server, const char *hostname, int port)
{
  server->addr = _resolv (server->conn, hostname, port);
  return server->addr ? RSE_OK : -1;
}

void
rs_server_set_timeout (struct rs_peer *server, int timeout)
{
  server->timeout = timeout;
}
void
rs_server_set_tries (struct rs_peer *server, int tries)
{
  server->tries = tries;
}

int
rs_server_set_secret (struct rs_peer *server, const char *secret)
{
  if (server->secret)
    free (server->secret);
  server->secret = (char *) malloc (strlen(secret) + 1);
  if (!server->secret)
    return rs_err_conn_push (server->conn, RSE_NOMEM, NULL);
  strcpy (server->secret, secret);
  return RSE_OK;
}

int
rs_conn_add_listener (struct rs_connection *conn, rs_conn_type_t type,
		      const char *hostname, int port)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

void
rs_conn_destroy (struct rs_connection *conn)
{
  struct rs_peer *p;

#warning "TODO: Disconnect active_peer."

  for (p = conn->peers; p; p = p->next)
    {
      if (p->addr)
	evutil_freeaddrinfo (p->addr);
      if (p->secret)
	rs_free (conn->ctx, p->secret);
    }

  if (conn->evb)
    event_base_free (conn->evb);
}

int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int rs_conn_set_callbacks(struct rs_connection *conn, struct rs_conn_callbacks *cb)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

int rs_conn_get_current_server(struct rs_connection *conn, const char *name, size_t buflen)
{
  return rs_err_conn_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}

