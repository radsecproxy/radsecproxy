#include <assert.h>
#include "libradsec.h"
#include "libradsec-impl.h"

const char *_errtxt[] = {
  "SUCCESS",			/* 0 RSE_OK */
  "NOMEM",			/* 1 RSE_NOMEM */
  "NYI -- not yet implemented",	/* 2 RSE_NOSYS */
  "invalid handle"		/* 3 RSE_INVALID_CTX */
  "invalid connection"		/* 4 RSE_INVALID_CONN */
  "ERR 5"			/*  RSE_ */
  "ERR 6"			/*  RSE_ */
  "ERR 7"			/*  RSE_ */
  "ERR 8"			/*  RSE_ */
  "ERR 9"			/*  RSE_ */
  "ERR 10"			/*  RSE_ */
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

static struct rs_error *
_err_new (unsigned int code, const char *msg)
{
  struct rs_error *err;

  err = malloc (sizeof (struct rs_error));
  if (err)
    {
      memset (err, 0, sizeof (struct rs_error));
      err->code = code;
      snprintf (err->buf, sizeof (err->buf), "%s: %s",
		code < sizeof (_errtxt) / sizeof (*_errtxt) ?
		_errtxt[code] : "invalid error index",
		msg);
    }
  return err;
}

int
rs_ctx_err_push (struct rs_handle *ctx, int code, const char *msg)
{
  struct rs_error *err = _err_new (code, msg);

  if (err)
    ctx->err = err;
  return code;
}

int
rs_conn_err_push (struct rs_connection *conn, int code, const char *msg)
{
  struct rs_error *err = _err_new (code, msg);

  if (err)
    conn->err = err;
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
rs_err_msg (struct rs_error *err)
{
  char *msg;

  if (err->msg)
    msg = err->msg;
  else
    msg = strdup (err->buf);

  rs_err_free (err);
  return msg;
}

int
rs_err_code (struct rs_error *err)
{
  int code = err->code;
  rs_err_free(err);
  return code;
}
