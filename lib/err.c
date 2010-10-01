/* See the file COPYING for licensing information.  */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "libradsec.h"
#include "libradsec-impl.h"

const char *_errtxt[] = {
  "SUCCESS",			/* 0 RSE_OK */
  "NOMEM",			/* 1 RSE_NOMEM */
  "NYI -- not yet implemented",	/* 2 RSE_NOSYS */
  "invalid handle"		/* 3 RSE_INVALID_CTX */
  "invalid connection"		/* 4 RSE_INVALID_CONN */
  "connection type mismatch"	/* 5 RSE_CONN_TYPE_MISMATCH */
  "FreeRadius error"		/* 6 RSE_FR */
  "bad hostname or port"	/* 7 RSE_BADADDR */
  "no peer configured"		/* 8 RSE_NOPEER */
  "libevent error"		/* 9 RSE_EVENT */
  "connection error"		/* 10 RSE_CONNERR */
  "ERR 11"			/*  RSE_ */
  "ERR 12"			/*  RSE_ */
  "ERR 13"			/*  RSE_ */
  "ERR "			/*  RSE_ */
  "ERR "			/*  RSE_ */
  "ERR "			/*  RSE_ */
  "ERR "			/*  RSE_ */
  "ERR "			/*  RSE_ */
  "ERR "			/*  RSE_ */
  "ERR "			/*  RSE_ */
  "some error"			/* 21 RSE_SOME_ERROR */
};
#define ERRTXT_SIZE (sizeof(_errtxt) / sizeof(*_errtxt))

static struct rs_error *
_err_new (unsigned int code, const char *file, int line, const char *fmt, va_list args)
{
  struct rs_error *err;

  err = malloc (sizeof(struct rs_error));
  if (err)
    {
      int n;
      memset (err, 0, sizeof(struct rs_error));
      err->code = code;
      if (fmt)
	n = vsnprintf (err->buf, sizeof(err->buf), fmt, args);
      else
	{
	  strncpy (err->buf,
		   err->code < ERRTXT_SIZE ? _errtxt[err->code] : "",
		   sizeof(err->buf));
	  n = strlen (err->buf);
	}
      if (n >= 0)
	{
	  char *sep = strrchr (file, '/');
	  if (sep)
	    file = sep + 1;
	  snprintf (err->buf + n, sizeof(err->buf) - n, " (%s: %d)", file,
		    line);
	}
    }
  return err;
}

static int
_ctx_err_vpush_fl (struct rs_handle *ctx, int code, const char *file, int line, const char *fmt, va_list args)
{
  struct rs_error *err = _err_new (code, file, line, fmt, args);

  if (err)
    ctx->err = err;
  return code;
}

int
rs_ctx_err_push (struct rs_handle *ctx, int code, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  _ctx_err_vpush_fl (ctx, code, NULL, 0, fmt, args);
  va_end (args);
  return code;
}

int
rs_ctx_err_push_fl (struct rs_handle *ctx, int code, const char *file, int line, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  _ctx_err_vpush_fl (ctx, code, file, line, fmt, args);
  va_end (args);
  return code;
}

static int
_conn_err_vpush_fl (struct rs_connection *conn, int code, const char *file, int line, const char *fmt, va_list args)
{
  struct rs_error *err = _err_new (code, file, line, fmt, args);

  if (err)
    conn->err = err;
  return code;
}

int
rs_conn_err_push (struct rs_connection *conn, int code, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  _conn_err_vpush_fl (conn, code, NULL, 0, fmt, args);
  va_end (args);
  return code;
}

int
rs_conn_err_push_fl (struct rs_connection *conn, int code, const char *file, int line, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  _conn_err_vpush_fl (conn, code, file, line, fmt, args);
  va_end (args);
  return code;
}

struct rs_error *
rs_ctx_err_pop (struct rs_handle *ctx)
{
  struct rs_error *err;

  if (!ctx)
    return NULL;		/* FIXME: RSE_INVALID_CTX.  */
  err = ctx->err;
  ctx->err = NULL;
  return err;
}

struct rs_error *
rs_conn_err_pop (struct rs_connection *conn)
{
  struct rs_error *err;

  if (!conn)
    return NULL;		/* FIXME: RSE_INVALID_CONN */
  err = conn->err;
  conn->err = NULL;
  return err;
}

void
rs_err_free (struct rs_error *err)
{
  assert (err);
  if (err->msg)
    free (err->msg);
  free (err);
}

char *
rs_err_msg (struct rs_error *err, int dofree_flag)
{
  char *msg;

  if (!err)
    return NULL;
  if (err->msg)
    msg = err->msg;
  else
    msg = strdup (err->buf);

  if (dofree_flag)
    rs_err_free (err);
  return msg;
}

int
rs_err_code (struct rs_error *err, int dofree_flag)
{
  int code;

  if (!err)
    return -1;
  code = err->code;

  if (dofree_flag)
    rs_err_free(err);
  return code;
}
