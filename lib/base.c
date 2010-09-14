#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
//#include <unistd.h>
#include <stdint.h>
#include "../tlv11.h"		/* FIXME: .. */
#include "libradsec-base.h"

static int
_do_connect(int type,
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

static struct list *
_list_new(const struct rs_handle *ctx)
{
    struct list *list = rs_malloc(ctx, sizeof(struct list));
    if (list)
	memset(list, 0, sizeof(struct list));
    return list;
}

static int
_list_push(const struct rs_handle *ctx, /* FIXME: code duplicate, list.c */
	   struct list *list,
	   void *data)
{
    struct list_node *node;

    node = rs_malloc(ctx, sizeof(struct list_node));
    if (!node)
	return 0;

    node->next = NULL;
    node->data = data;

    if (list->first)
	list->last->next = node;
    else
	list->first = node;
    list->last = node;

    list->count++;
    return 1;
}

static void
_list_destroy(const struct rs_handle *ctx, /* FIXME: code dup */
	      struct list *list)
{
    struct list_node *node, *next;

    if (list) {
	for (node = list->first; node; node = next) {
	    rs_free(ctx, node->data);
	    next = node->next;
	    rs_free(ctx, node);
	}
	free(list);
    }
}

/* ------------------------------------------------------- */
int
rs_connect(const struct rs_handle *conf,
	   const struct sockaddr *addr,
	   socklen_t addrlen)
{
    switch (conf->conn_type)
    {
    case RS_CONN_TYPE_UDP:
	return _do_connect(SOCK_DGRAM, addr, addrlen);
    case RS_CONN_TYPE_TCP:
	return _do_connect(SOCK_STREAM, addr, addrlen);
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
rs_disconnect( const struct rs_handle *conf, int fd)
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
rs_packet_new(const struct rs_handle *ctx,
	      const uint8_t buf[RS_HEADER_LEN],
	      size_t *count)
{
    struct rs_packet *p = rs_malloc(ctx, sizeof(struct rs_packet));
    if (p) {
	p->attrs = _list_new(ctx);
	if (p->attrs) {
	    p->code = buf[0];
	    p->id = buf[1];
	    if (count)
		*count = (buf[2] << 8) + buf[3];
	}
	else
	    rs_packet_free(ctx, &p);
    }
    return p;
}

struct rs_packet *
rs_packet_parse(const struct rs_handle *ctx,
		struct rs_packet **packet,
		const uint8_t *buf,
		size_t buflen)
{
    struct rs_packet *p = *packet;
    struct tlv *tlv;
    size_t i;
    uint8_t atype, alen;

    if (buflen < 16) {
	errno = EPROTO;
	rs_packet_free(ctx, &p);
	return NULL;
    }

    i = 16;
    while (i + 2 < buflen) {
	atype = buf[i++];
	alen = buf[i++];
	if (alen < 2) {
#if DEBUG
	    fprintf(stderr,
		    "%s: DEBUG: attribute (type %d, len %d) has an invalid length\n",
		    __func__, atype, alen);
#endif
	    errno = EPROTO;
	    rs_packet_free(ctx, &p);
	    return NULL;
	}
	alen -= 2;
	if (alen + i >= buflen) {
#if DEBUG
	    fprintf(stderr,
		    "%s: DEBUG: attribute (type %d, len %d) wouldn't fit packet\n",
		    __func__, atype, alen);
#endif
	    errno = EPROTO;
	    rs_packet_free(ctx, &p);
	    return NULL;
	}
	tlv = maketlv(atype, alen, (void *) (buf + i));
	if (tlv)
	    _list_push(ctx, p->attrs, tlv);
	else {
	    errno = ENOMEM;
	    rs_packet_free(ctx, &p);
	}
	i += alen;
    }
    memcpy(p->auth, buf, 16);
    return p;
}

void
rs_packet_free(const struct rs_handle *ctx,
	       struct rs_packet **packet)
{
    _list_destroy(ctx, (*packet)->attrs);
    rs_free(ctx, *packet);
    *packet = NULL;
}

ssize_t
rs_packet_serialize(const struct rs_packet *packet,
		    uint8_t *buf,
		    size_t buflen)
{
    struct list_node *ln;
    size_t pktlen;
    ssize_t i;

    for (ln = list_first(packet->attrs), pktlen = 20; ln; ln = list_next(ln))
	pktlen += ((struct rs_attribute *)(ln->data))->length;
    if (pktlen > buflen)
	return -(pktlen - buflen);

    buf[0] = packet->code;
    buf[1] = packet->id;
    buf[2] = (pktlen & 0xff00) >> 8;
    buf[3] = pktlen & 0xff;

    memcpy(buf + 4, packet->auth, 16);

    for (ln = list_first(packet->attrs), i = 20; ln; ln = list_next(ln)) {
	struct rs_attribute *a = (struct rs_attribute *)(ln->data);
	buf[i++] = a->type;
	buf[i++] = a->length;
	memcpy(buf + i, a->value, a->length - 2);
	i += a->length - 2;
    }

    return i;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
