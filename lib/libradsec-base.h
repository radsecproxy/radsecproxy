/** @file libradsec-minimal.h
    @brief Low level API for libradsec.  */

/* FIXME: License blurb goes here.  */

#include "libevent.h"

/* Example usage.  */
#if 0
{
  fd = rs_connect (address, psk);
  if (!fd)
    /* check errno */ ;
  n = read (fd, buf, buflen);
  struct rs_packet *p = rs_packet_new (buf, buflen, &count);
  if (!p)
    {
      if (count < 0)
	/* check errno */ ;
      else
	/* need another COUNT octets */ ;
    }
  else
    /* next unused octet is at buf+count */

  n = rs_packet_serialize (p, buf, buflen);
  if (n < 0)
    /* invalid packet */ ;
  else if (n == 0)
    /* out of buffer space */ ;
  else
    write (fd, buf, n);

  if (p)
    rs_packet_free(p);
  if (fd)
    rs_disconnect(fd);
}
#endif


/* Function prototypes.  */

/** Establish a connection.

    @param type Connection type.
    @param addr Network address to connect to.
    @param cred Credentials, or NULL.

    @return A file descriptor or -1 if an error occurred, in which
    case errno is set appropriately.  */
int rs_connect(enum rs_conn_type type,
	       const struct sockaddr_storage *addr,
	       const struct rs_credentials *cred);

/** Disconnect.

    @param fd File descriptor to close.

    @return 0 on success or -1 if an error occurred, in which case
    errno is set appropriately.  */
int rs_disconnect(int fd);

/** Allocate and initialize a packet object from a buffer containing a
    packet as seen on the wire.  Free the packet using @a
    rs_packet_free().

    @param buf
    @param buflen
    @param count

    @return Packet or NULL on error or not enough data in @a buf.  If
    return value is NULL and @a count is < 0, an error has occurred
    and errno is set appropriately.  If return value is NULL and @a
    count is > 0 it shows the number of bytes needed to complete the
    packet.
*/
struct rs_packet *rs_packet_new(const uint8_t *buf,
				size_t buflen,
				ssize_t *count);

/** Free a packet object that has been allocated by @a
    rs_packet_new().


*/
void rs_packet_free(struct rs_packet *packet);

/** Serialize a packet.  */
ssize_t rs_packet_serialize(const struct rs_packet *packet,
			    uint8_t *buf,
			    size_t buflen);
