#include <string.h>
#include <assert.h>
#include <freeradius/libradius.h>
#include "libradsec.h"
#include "libradsec-impl.h"
#if defined DEBUG
#include "debug.h"
#endif

int
_packet_create (struct rs_connection *conn, struct rs_packet **pkt_out,
		int code)
{
  struct rs_packet *p;
  RADIUS_PACKET *rpkt;

  *pkt_out = NULL;

  rpkt = rad_alloc (1);
  if (!rpkt)
    return rs_conn_err_push (conn, RSE_NOMEM, __func__);
  rpkt->id = -1;
  rpkt->code = code;

  p = (struct rs_packet *) malloc (sizeof (struct rs_packet));
  if (!p) {
    rad_free (&rpkt);
    return rs_conn_err_push (conn, RSE_NOMEM, __func__);
  }
  memset (p, 0, sizeof (struct rs_packet));
  p->rpkt = rpkt;

  *pkt_out = p;
  return RSE_OK;
}

int
rs_packet_create_acc_request (struct rs_connection *conn,
			      struct rs_packet **pkt_out,
			      const char *user_name, const char *user_pw)
{
  struct rs_packet *pkt;
  struct rs_attr *attr;

  if (_packet_create (conn, pkt_out, PW_AUTHENTICATION_REQUEST))
    return -1;
  pkt = *pkt_out;

  if (rs_attr_create (conn, &attr, "User-Name", user_name))
    return -1;
  rs_packet_add_attr (pkt, attr);

  if (rs_attr_create (conn, &attr, "User-Password", user_name))
    return -1;
  /* FIXME: need this too? rad_pwencode(user_pw, &pwlen, SECRET, reqauth) */
  rs_packet_add_attr (pkt, attr);

  return RSE_OK;
}

int
rs_packet_send (struct rs_connection *conn, const struct rs_packet *pkt,
		void *user_data)
{
  assert (pkt->rpkt);

  if (!conn->active_peer)
    {
      int err = rs_conn_open (conn);
      if (err)
	return err;
      }
  rad_encode (pkt->rpkt, NULL, conn->active_peer->secret);
#if defined (DEBUG)
  fprintf (stderr, "%s: about to send this to %s", __func__, "fixme");
  rs_dump_packet (pkt);
#endif

  return RSE_NOSYS;
}

int rs_packet_receive(struct rs_connection *conn, struct rs_packet **pkt)
{
  return RSE_NOSYS;
}

void
rs_packet_add_attr(struct rs_packet *pkt, struct rs_attr *attr)
{
  pairadd (&pkt->rpkt->vps, attr->vp);
  attr->pkt = pkt;
}
