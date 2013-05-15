/* Copyright 2011, NORDUnet A/S. All rights reserved. */
/* See LICENSE for licensing information. */

#include <stdlib.h>
#include <stdio.h>
#include "udp.h"

ssize_t
handle_data (const uint8_t *buf, ssize_t len)
{
  return hd (buf, len);
}

int
main (int argc, char *argv[])
{
  int n, i;
  struct timeval tv;
  struct polldata *data;

#define TIMEOUT 1 		/* Seconds.  */

  tv.tv_sec = TIMEOUT;
  tv.tv_usec = 0;
  data = udp_server (argv[1], &tv, handle_data);

  for (i = 0, n = udp_poll (data); n == 0 && i < 3; n = udp_poll (data), i++)
    {
      fprintf (stderr, "waiting another %ld second%s\n",
	       tv.tv_sec, tv.tv_sec > 1 ? "s" : "");
    }

  udp_free_polldata (data);
  return (n <= 0);
}
