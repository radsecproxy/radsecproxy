/* Copyright 2012-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#include <stdlib.h>
#include <string.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "util.h"

char *
rs_strdup (struct rs_context *ctx, const char *s)
{
  size_t len;
  char *buf;

  len = strlen (s);
  buf = rs_malloc (ctx, len + 1);

  if (buf != NULL)
    memcpy (buf, s, len + 1);
  else
    rs_err_ctx_push (ctx, RSE_NOMEM, __func__);

  return buf;
}
