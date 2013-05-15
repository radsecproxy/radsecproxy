/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <assert.h>
#include <radius/client.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "debug.h"

void
rs_dump_message (const struct rs_message *msg)
{
  const RADIUS_PACKET *p = NULL;

  if (!msg || !msg->rpkt)
    return;
  p = msg->rpkt;

  fprintf (stderr, "\tCode: %u, Identifier: %u, Lenght: %zu\n",
	   p->code,
	   p->id,
	   p->sizeof_data);
  fflush (stderr);
}

#if defined DEBUG
int
_rs_debug (const char *fmt, ...)
{
  int n;
  va_list args;

  va_start (args, fmt);
  n = vfprintf (stderr, fmt, args);
  va_end (args);
  fflush (stderr);

  return n;
}
#endif
