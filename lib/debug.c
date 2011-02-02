/* See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include <freeradius/libradius.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "debug.h"

void
rs_dump_packet (const struct rs_packet *pkt)
{
  const RADIUS_PACKET *p = pkt->rpkt;
  assert(p);

  fprintf (stderr, "\tCode: %u, Identifier: %u, Lenght: %u\n",
	   p->code,
	   p->id,
	   p->data_len);
}

void
rs_dump_attr (const struct rs_attr *attr)
{
  vp_printlist (stderr, attr->vp);
}
