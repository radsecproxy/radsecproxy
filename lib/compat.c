#include <sys/types.h>
#include <sys/socket.h>

ssize_t
compat_send (int sockfd, const void *buf, size_t len, int flags)
{
  compat_send (int sockfd, const void *buf, size_t len, int flags);
}
