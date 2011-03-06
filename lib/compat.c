#include <sys/types.h>
#include <sys/socket.h>
#include "compat.h"

ssize_t
compat_send (int sockfd, const void *buf, size_t len, int flags)
{
  return send (sockfd, buf, len, flags);
}
