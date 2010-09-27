#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libgen.h>

#include <freeradius/libradius.h>
#include "libradsec.h"
#include "libradsec-impl.h"

int
rs_context_create(struct rs_handle **ctx, const char *dict)
{
  struct rs_handle *h;

  *ctx = NULL;
  h = (struct rs_handle *) malloc (sizeof (struct rs_handle));
  if (h)
    {
      char *buf;
      char *dir, *fn;

      buf = malloc (strlen (dict) + 1);
      if (!buf)
	{
	  free (h);
	  return RSE_NOMEM;
	}
      strcpy (buf, dict);
      dir = dirname (buf);
      free (buf);
      strcpy (buf, dict);
      fn = basename (buf);
      free (buf);
      if (dict_init (dir, fn) < 0)
	{
	  free (h);
	  return RSE_SOME_ERROR;
	}
#if defined (DEBUG)
      fr_log_fp = stderr;
      fr_debug_flag = 1;
#endif
      fr_randinit (&h->fr_randctx, 0);
      fr_rand_seed (NULL, 0);

      *ctx = h;
    }
  return (h ? RSE_OK : RSE_NOMEM);
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

int rs_conn_create(const struct rs_handle *ctx, struct rs_connection **conn)
{
  return RSE_NOSYS;
}

int rs_conn_add_server(struct rs_connection  *conn, rs_conn_type_t type, const char *host, int port, int timeout, int tries, const char *secret)
{
  return RSE_NOSYS;
}

int rs_conn_add_listener(struct rs_connection  *conn, rs_conn_type_t type, const char *host, int port, const char *secret)
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
