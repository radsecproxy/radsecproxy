/* Example usage of libradsec-base, using blocking i/o.  */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "blocking.h"

struct rs_packet *
next_packet (const struct rs_handle *ctx, int fd)
{
  uint8_t hdr[RS_HEADER_LEN];
  uint8_t *buf;
  size_t len;
  struct rs_packet *p;
  ssize_t n;

  /* Read fixed length header.  */
  n = 0;
  while (n < RS_HEADER_LEN)
    n += read (fd, hdr, RS_HEADER_LEN - n);

  p = rs_packet_new (ctx, hdr, &len);
  fprintf (stderr, "DEBUG: got header, total packet len is %d\n",
	   len + RS_HEADER_LEN);

  /* Read the rest of the message.  */
  if (p)
    {
      buf = malloc (len);
      if (buf)
	{
	  n = 0;
	  while (n < len)
	    n += read (fd, buf, len - n);
	  p = rs_packet_parse (ctx, &p, buf, len);
	  free (buf);
	}
      else
	rs_packet_free (ctx, &p);
    }

  return p;
}

int
send_packet(const struct rs_handle *ctx, int fd, struct rs_packet *p)
{
  uint8_t *buf = NULL;
  ssize_t n = -20;	      /* Arbitrary packet size -- a guess.  */

  while (n < 0)
    {
      buf = realloc (buf, -n);
      if (buf == NULL)
	return -1;
      n = rs_packet_serialize (p, buf, -n);
    }

  while (n)
    {
      ssize_t count = write (fd, buf, n);
      if (count == -1)
	return -1;
      n -= count;
    }

  free (buf);
  rs_packet_free (ctx, &p);
  return 0;
}
