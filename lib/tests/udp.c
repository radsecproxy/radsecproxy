#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <event2/event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include "udp.h"

static struct addrinfo *
_resolve (const char *str)
{
  static int first = 1;
  static struct addrinfo hints, *result = NULL;
  struct addrinfo *rp = NULL;
  int r;

  if (first)
    {
      first = 0;
      memset (&hints, 0, sizeof (hints));
      hints.ai_family = AF_INET; /* AF_UNSPEC */
      hints.ai_socktype = SOCK_DGRAM;
      r = getaddrinfo (NULL, str, &hints, &result);
      if (r)
	fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (r));
    }

  if (result)
    {
      rp = result;
      result = result->ai_next;
    }

  return rp;
}

void
udp_free_polldata (struct polldata *data)
{
  if (data)
    {
      if (data->timeout)
	free (data->timeout);
      free (data);
    }
}

/* @return if select() returns error or timeout, return select()
   else return value from invoked callback function */
ssize_t
udp_poll (struct polldata *data)
{
  int r;
  long timeout;
  fd_set rfds;
  ssize_t len;
  uint8_t buf[RS_MAX_PACKET_LEN];

  FD_ZERO (&rfds);
  FD_SET (data->s, &rfds);
  if (data->timeout)
    timeout = data->timeout->tv_sec; /* Save from destruction (Linux).  */
  //fprintf (stderr, "calling select with timeout %ld\n", timeout);
  r = select (data->s + 1, &rfds, NULL, NULL, data->timeout);
  if (data->timeout)
    data->timeout->tv_sec = timeout; /* Restore.  */
  //fprintf (stderr, "select returning %d\n", r);
  if (r > 0)
    {
      len = recv (data->s, buf, sizeof (buf), 0);
      if (len > 0)
	return data->cb (buf, len);
    }
  return r;
}

struct polldata *
udp_server (const char *bindto, struct timeval *timeout, data_cb cb)
{
  struct addrinfo *res;
  int s = -1;

  for (res = _resolve (bindto); res; res = _resolve (bindto))
    {
      s = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
      if (s >= 0)
	{
	  if (bind (s, res->ai_addr, res->ai_addrlen) == 0)
	    break;		/* Done.  */
	  else
	    {
	      close (s);
	      s = -1;
	    }
	}
    }

  if (s >= 0)
    {
      struct polldata *data = malloc (sizeof (struct polldata));
      assert (data);
      memset (data, 0, sizeof (struct polldata));
      data->s = s;
      data->cb = cb;
      if (timeout)
	{
	  data->timeout = malloc (sizeof (struct timeval));
	  assert (data->timeout);
	  memcpy (data->timeout, timeout, sizeof (struct timeval));
	}
      return data;
    }

  return NULL;
}

ssize_t
hd (const uint8_t *buf, ssize_t len)
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
