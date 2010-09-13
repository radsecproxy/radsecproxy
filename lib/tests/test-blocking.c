#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include "blocking.h"

int
f (const struct sockaddr *addr,
   socklen_t addrlen,
   int out_fd)
{
  int fd = -1;
  //struct rs_alloc_scheme as = { calloc, malloc, free, realloc };
  struct rs_config ctx = { RS_CONN_TYPE_TCP,
			   { RS_CRED_NONE, NULL, NULL },
			   { NULL, NULL, NULL, NULL } };
  struct rs_packet *p = NULL;

  fd = rs_connect (&ctx, addr, addrlen);
  if (fd < 0)
    {
      perror ("rs_connect");
      return -1;
    }

  p = next_packet (&ctx, fd);
  if (p == NULL)
    {
      perror ("next_packet");
      rs_disconnect (&ctx, fd);
      return -1;
    }
  rs_disconnect (&ctx, fd);

  if (send_packet (&ctx, out_fd, p))
    {
      rs_packet_free (&ctx, &p);
      perror ("send_packet");
      return -1;
    }

    return 0;
}

int
main (int argc, char *argv[])
{
  struct addrinfo *ai;
  int rc;

  rc = getaddrinfo (argv[1], argv[2], NULL, &ai);
  if (rc)
    {
      if (rc == EAI_SYSTEM)
	perror ("getaddrinfo");
      else
	fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (rc));
      return -1;
    }

  return f (ai->ai_addr, ai->ai_addrlen, 1);
}
