/** @file libradsec-base.h
    @brief Low level API for libradsec.  */

/* FIXME: License blurb goes here.  */

#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include "libradsec.h"

/* Function prototypes.  */

/** Establish a connection.

    @param type Connection type.
    @param addr Network address to connect to.
    @param cred Credentials, or NULL.

    @return A file descriptor or -1 if an error occurred, in which
    case errno is set appropriately.  */
int rs_connect(const struct rs_config *conf,
	       const struct sockaddr *addr,
	       socklen_t addrlen);

/** Disconnect.

    @param fd File descriptor to close.

    @return 0 on success or -1 if an error occurred, in which case
    errno is set appropriately.  */
int rs_disconnect(const struct rs_config *conf,
		  int fd);

/** Allocate and initialize a packet from a buffer containing a packet
    as seen on the wire.  Free the packet using @a rs_packet_free().

FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME

    @param buf Buffer with on-the-wire data with packet.
    @param buflen Number of octets in @a buf.

    @param count Number of octets used in buffer, in case of
    successful construction of a packet (return !NULL) or number of
    octets needed for a complete packet (return NULL).

FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME

    @return Packet or NULL on error or not enough data in @a buf.  If
    return value is NULL and @a count is < 0, an error has occurred
    and errno is set appropriately.  If return value is NULL and @a
    count is > 0 it shows the number of bytes needed to complete the
    packet.  */
struct rs_packet *rs_packet_new(const struct rs_config *ctx,
				const uint8_t buf[RS_HEADER_LEN],
				size_t *count);

/* FIXME: if return NULL, @a packet is freed and the pointer is no longer valid!  */
struct rs_packet *rs_packet_parse(const struct rs_config *ctx,
				  struct rs_packet **packet,
				  const uint8_t *buf,
				  size_t buflen);

/** Free a packet that has been allocated by @a rs_packet_new().

    @param packet Packet to free.
    FIXME
*/
void rs_packet_free(const struct rs_config *ctx,
		    struct rs_packet **packet);

/** Serialize a packet.

    @param packet Packet to serialize.
    @param buf Buffer to store the serialized packet in.
    @param buflen Length of buffer.

    @return Number of bytes written to buf or 0 if the buffer wasn't
    large enough to hold the packet or < 0 in case the packet couldn't
    be serialized for some other eason (FIXME: elaborate) */

ssize_t rs_packet_serialize(const struct rs_packet *packet,
			    uint8_t *buf,
			    size_t buflen);
