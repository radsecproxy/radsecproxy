/* RADIUS/RadSec client using libradsec in on-your-own mode. */

#include <sys/select.h>
#include <errno.h>
#include <stdio.h>

int
loop ()
{
  int n;
  fd_set rfds, wfds, xfds;
  //struct timeval timeout = {1,0}; /* 1 second. */

  fd = FIXME;

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  FD_ZERO(&wfds);
  FD_SET(fd, &wfds);
  FD_ZERO(&xfds);
  FD_SET(fd, &xfds);

  while (1)
    {
      n = select (fd + 1, &rfds, &wfds, &xfds, NULL);
      if (n == 0)
        {
          /* Timeout. */
          fprintf (stderr, "timeout on fd %d after %d seconds\n", fd,
                   timeout.tv_sec);
          return -1;
        }
      else if (n == -1)
        {
          /* Error. */
          perror ("select");
          return -errno;
        }
      else
        {
          /* Ready to read/write/<had error>. */
          if (FD_ISSET(fd, &rfds))
            {
              printf ("reading msg\n");
              radsec_recv_blocking(fd, &msg_in);
              if (!verify_packet(&msg_in))
            }
          if (FD_ISSET(fd, &wfds))
            {
              radsec_send(fd, &msg_out);
              printf ("msg sent\n");
            }
          if (FD_ISSET(fd, &xfds))
            {
              fprintf (stderr, "error on fd %d\n", fd);
              return -1;
            }
        }
    }
}

int
main (int argc, char *argv[])
{
  return loop ();
}
