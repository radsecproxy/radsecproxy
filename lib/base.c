#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include "libradsec-base.h"

static int
do_connect(int type,
	   const struct sockaddr *addr,
	   socklen_t addrlen)
{
  int s;

  s = socket(AF_INET, type, 0); /* FIXME: do AF_INET6 too */
  if (s >= 0)
      if (connect(s, addr, addrlen)) {
	  close(s);
	  s = -1;
      }
  return s;
}

int
rs_connect(const struct rs_config *conf,
	   const struct sockaddr *addr,
	   socklen_t addrlen)
{
    switch (conf->conn_type)
    {
    case RS_CONN_TYPE_UDP:
	return do_connect(SOCK_DGRAM, addr, addrlen);
    case RS_CONN_TYPE_TCP:
	return do_connect(SOCK_STREAM, addr, addrlen);
	/* fall thru */
    case RS_CONN_TYPE_TLS:
	/* fall thru */
    case RS_CONN_TYPE_DTLS:
	/* fall thru */
    default:
	errno = ENOSYS;
	return -1;
    }
}

int
rs_disconnect( const struct rs_config *conf, int fd)
{
    switch (conf->conn_type)
    {
    case RS_CONN_TYPE_UDP:
	return close(fd);
    case RS_CONN_TYPE_TCP:
	shutdown(fd, SHUT_RDWR);
	return close(fd);
    case RS_CONN_TYPE_TLS:
	/* fall thru */
    case RS_CONN_TYPE_DTLS:
	/* fall thru */
    default:
	errno = ENOSYS;
	return -1;
    }
}

struct rs_packet *
rs_packet_new(const struct rs_config *ctx,
	      const uint8_t buf[RS_HEADER_LEN],
	      size_t *count)
{
    struct rs_packet *p =
	(ctx->alloc_scheme.malloc ? ctx->alloc_scheme.malloc : malloc)(20);
    if (p) {
	p->code = buf[0];
	p->id = buf[1];
	if (count)
	    *count = 256 * buf[2] + buf[3];
    }
    return p;
}

struct rs_packet *
rs_packet_parse(const struct rs_config *ctx,
		struct rs_packet *packet,
		const uint8_t *buf,
		size_t buflen)
{
    if (buflen < 16) {
	rs_packet_free(ctx, packet);
	errno = EPROTO;
	return NULL;
    }
    memcpy(packet->auth, buf, 16);
    /* TODO: copy attributes starting at buf[16].  */
    return packet;
}

void
rs_packet_free(const struct rs_config *ctx,
	       struct rs_packet *packet)
{
    (ctx->alloc_scheme.free ? ctx->alloc_scheme.free : free)(packet);
}

ssize_t
rs_packet_serialize(const struct rs_packet *packet,
		    uint8_t *buf,
		    size_t buflen)
{
    fixme;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
