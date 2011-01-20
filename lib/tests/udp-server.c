#include <stdlib.h>
#include <stdio.h>
#include "udp.h"

ssize_t
handle_data (const uint8_t *buf, ssize_t len)
{
  int i;

  printf ("# len: %ld\n", len);
  for (i = 0; i < len; i++)
    {
      printf ("%02x%s", buf[i], (i+1) % 8 ? " " : "   ");
      if ((i + 1) % 16 == 0)
	printf ("\n");
    }
  printf ("\n");
  return len;
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

  if (data)
    {
      if (data->timeout)
	free (data->timeout);
      free (data);
    }
  return (n <= 0);
}
