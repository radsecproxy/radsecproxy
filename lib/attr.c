/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

/* NOTE: This file is not in use at the moment (libradsec-0.0.1).  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <radius/client.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

int
rs_attr_create(struct rs_connection *conn,
	       struct rs_attr **attr,
	       const char *type,
	       const char *val)
{
  VALUE_PAIR *vp;
  struct rs_attr *a;

  *attr = NULL;
  a = (struct rs_attr *) malloc (sizeof(struct rs_attr));
  if (!a)
    return rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);
  memset (a, 0, sizeof(struct rs_attr));

  vp = pairmake (type, val, T_OP_EQ);
  if (!vp)
    {
      rs_attr_destroy (a);
      return rs_err_conn_push_fl (conn, RSE_FR, __FILE__, __LINE__,
				  "pairmake: %s", fr_strerror ());
    }

  a->vp = vp;
  *attr = a;
  return RSE_OK;
}

void
rs_attr_destroy (struct rs_attr *attr)
{
  if (attr->vp)
    pairfree (&attr->vp);
  free (attr);
}
