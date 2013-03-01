/* Copyright 2012 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

#include <string.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "util.h"

char *
rs_strdup (struct rs_context *ctx, const char *s)
{
  char *buf = rs_calloc (ctx, 1, strlen (s) + 1);

  if (buf)
    strcpy (buf, s);
  else
    rs_err_ctx_push (ctx, RSE_NOMEM, NULL);

  return buf;
}
