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
int rs_connect(const struct rs_handle *conf, const struct sockaddr *addr,
	       socklen_t addrlen);

/** Disconnect.
    @param fd File descriptor to close.
    @return 0 on success or -1 if an error occurred, in which case
    errno is set appropriately.  */
int rs_disconnect(const struct rs_handle *conf, int fd);

/** Allocate and initialize a packet from a buffer containing a RADIUS
    message header.  The packet should be freed using @a
    rs_packet_free().
    @param ctx Context.
    @param buf Buffer with on-the-wire data with RADIUS message
    header.
    @param count Optionally a pointer to a size_t where the number of
    additional octets needed to complete the RADIUS message will be
    written.  Or NULL.
    @return A pointer to a newly allocated packet or NULL on error.
*/
struct rs_packet *rs_packet_new(const struct rs_handle *ctx,
				const uint8_t buf[RS_HEADER_LEN],
				size_t *count);

/** Parse an on wire RADIUS packet and store it in @a packet.
    @param ctx Context.
    @param packet A pointer to the address of a struct rs_packet
    allocated by @a rs_packet_new().  Will be freed if an error
    occurs.
    @param buf Buffer with on-the-wire data with RADIUS message, not
    including the four octet RADIUS header.
    @param buflen Number of octets in @a buf.
    @return *packet or NULL on error.  If NULL, the packet has been
    freed and *packet is no longer valid.
*/
struct rs_packet *rs_packet_parse(const struct rs_handle *ctx,
				  struct rs_packet **packet,
				  const uint8_t *buf,
				  size_t buflen);

/** Free a packet that has been allocated by @a rs_packet_new().
    @param ctx Context.
    @param packet Packet to free.
*/
void rs_packet_free(const struct rs_handle *ctx, struct rs_packet **packet);

/** Serialize a packet.
    @param packet Packet to serialize.
    @param buf Buffer to store the serialized packet in.
    @param buflen Length of buffer.
    @return Number of bytes written to buf or 0 if the buffer wasn't
    large enough to hold the packet or < 0 in case the packet couldn't
    be serialized for some other reason (FIXME: elaborate) */

ssize_t rs_packet_serialize(const struct rs_packet *packet,
			    uint8_t *buf, size_t buflen);
