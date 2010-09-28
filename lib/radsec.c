#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>

#include <freeradius/libradius.h>
#include "libradsec.h"
#include "libradsec-impl.h"

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
  return RSE_NOSYS;
}

int rs_context_config_read(struct rs_handle *ctx, const char *config_file)
{
  return RSE_NOSYS;
}

int rs_conn_create(struct rs_handle *ctx, struct rs_connection **conn)
{
  struct rs_connection *c;

  c = (struct rs_connection *) malloc (sizeof(struct rs_connection));
  if (c)
    {
      memset (c, 0, sizeof(struct rs_connection));
      c->ctx = ctx;
      c->peers.next = &c->peers;
    }
  if (conn)
    *conn = c;
  return c ? RSE_OK : rs_ctx_err_push (ctx, RSE_NOMEM, NULL);
}

struct addrinfo *
_resolv (const char *host, int port)
{
  return NULL;
}

int rs_conn_add_server(struct rs_connection *conn, struct rs_peer **server, rs_conn_type_t type, const char *host, int port)
{
  struct rs_peer *srv;

  if (conn->type == RS_CONN_TYPE_NONE)
    conn->type = type;
  else if (conn->type != type)
    return rs_conn_err_push (conn, RSE_CONN_TYPE_MISMATCH, NULL);

  srv = (struct rs_peer *) malloc (sizeof(struct rs_peer));
  if (srv)
    {
      memset (srv, 0, sizeof(struct rs_peer));
      srv->conn = conn;
      srv->addr = _resolv (host, port);
      srv->timeout = 10;
      srv->tries = 3;
      srv->next = conn->peers.next;
      conn->peers.next = srv;
    }
  if (*server)
    *server = srv;
  return srv ? RSE_OK : rs_conn_err_push (conn, RSE_NOMEM, NULL);
}

void rs_server_set_timeout(struct rs_peer *server, int timeout)
{
  server->timeout = timeout;
}
void rs_server_set_tries(struct rs_peer *server, int tries)
{
  server->tries = tries;
}
int rs_server_set_secret(struct rs_peer *server, const char *secret)
{
  if (server->secret)
    free (server->secret);
  server->secret = (char *) malloc (strlen(secret) + 1);
  if (!server->secret)
    return rs_conn_err_push (server->conn, RSE_NOMEM, NULL);
  strcpy (server->secret, secret);
  return RSE_OK;
}

int rs_conn_add_listener(struct rs_connection *conn, rs_conn_type_t type, const char *host, int port)
{
  return RSE_NOSYS;
}

int rs_conn_destroy(struct rs_connection  *conn)
{
  return RSE_NOSYS;
}

int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb)
{
  return RSE_NOSYS;
}

int rs_conn_set_callbacks(struct rs_connection *conn, struct rs_conn_callbacks *cb)
{
  return RSE_NOSYS;
}

int rs_conn_set_server(struct rs_connection *conn, const char *name)
{
  return RSE_NOSYS;
}

int rs_conn_get_server(const struct rs_connection *conn, const char *name, size_t buflen)
{
  return RSE_NOSYS;
}

int rs_conn_open(struct rs_connection *conn)
{
  return rs_conn_err_push_fl (conn, RSE_NOSYS, __FILE__, __LINE__,
			      "%s: NYI", __func__);
}
