/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include "compat.h"

ssize_t
compat_send (int sockfd, const void *buf, size_t len, int flags)
{
  return send (sockfd, buf, len, flags);
}

ssize_t
compat_recv (int sockfd, void *buf, size_t len, int flags)
{
  return recv (sockfd, buf, len, flags);
}
