/* Copyright 2011 JANET(UK). All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <radsec/radsec.h>
#include <radius/client.h>

#define RS_ERR(err) ((err) < 0 ? -err : RSE_OK)

void
rs_avp_free (rs_avp **vps)
{
  nr_vp_free (vps);
}

size_t
rs_avp_length (rs_const_avp *vp)
{
  if (vp == NULL)
    return 0;

  return vp->length;
}

rs_attr_type_t
rs_avp_typeof (rs_const_avp *vp)
{
  if (vp == NULL)
    return RS_TYPE_INVALID;

  return vp->da->type;
}

void
rs_avp_attrid (rs_const_avp *vp,
	       unsigned int *attr,
	       unsigned int *vendor)
{
  assert (vp != NULL);

  *attr = vp->da->attr;
  *vendor = vp->da->vendor;
}

const char *
rs_avp_name (rs_const_avp *vp)
{
  return (vp != NULL) ? vp->da->name : NULL;
}

void
rs_avp_append (rs_avp **head, rs_avp *tail)
{
  nr_vps_append (head, tail);
}

rs_avp *
rs_avp_find (rs_avp *vp, unsigned int attr, unsigned int vendor)
{
  if (vp == NULL)
    return NULL;

  return nr_vps_find (vp, attr, vendor);
}

rs_const_avp *
rs_avp_find_const (rs_const_avp *vp,
                   unsigned int attr, unsigned int vendor)
{
  if (vp == NULL)
    return NULL;

  return nr_vps_find ((rs_avp *)vp, attr, vendor);
}

rs_avp *
rs_avp_alloc (unsigned int attr, unsigned int vendor)
{
  const DICT_ATTR *da;
  VALUE_PAIR *vp;

  da = nr_dict_attr_byvalue (attr, vendor);
  if (da == NULL) {
    vp = nr_vp_alloc_raw (attr, vendor);
  } else {
    vp = nr_vp_alloc (da);
  }

  if (vp == NULL)
    return NULL;

  return vp;
}

rs_avp *
rs_avp_dup (rs_const_avp *vp)
{
  rs_avp *vp2;

  if (vp->da->flags.unknown)
    vp2 = nr_vp_alloc_raw (vp->da->attr, vp->da->vendor);
  else
    vp2 = nr_vp_alloc (vp->da);
  if (vp2 == NULL)
    return NULL;

  vp2->length = vp->length;
  vp2->tag = vp->tag;
  vp2->next = NULL;

#ifdef RS_TYPE_TLV
  if (rs_avp_is_tlv (vp)) {
    vp2->vp_tlv = malloc (vp->length);
    if (vp2->vp_tlv == NULL) {
      rs_avp_free (vp2);
      return NULL;
    }
    memcpy (vp2->vp_tlv, vp->vp_tlv, vp->length);
    return vp2;
  }
#endif

  memcpy (vp2->vp_strvalue, vp->vp_strvalue, vp->length);
  if (rs_avp_is_string (vp))
    vp2->vp_strvalue[vp->length] = '\0';

  return vp2;
}

rs_avp *
rs_avp_next (rs_avp *vp)
{
  return (vp != NULL) ? vp->next : NULL;
}

rs_const_avp *
rs_avp_next_const (rs_const_avp *vp)
{
  return (vp != NULL) ? vp->next : NULL;
}

int
rs_avp_delete (rs_avp **first,
               unsigned int attr, unsigned int vendor)
{
  int found = 0;
  rs_avp **p;

  for (p = first; *p != NULL; p++) {
    if ((*p)->da->attr == attr &&
        (*p)->da->vendor == vendor) {
      rs_avp *next = (*p)->next;

      (*p)->next = NULL;
      rs_avp_free (p);

      *p = next;
      found++;
    }
  }

  return found ? RSE_OK : RSE_ATTR_UNKNOWN;
}

const char *
rs_avp_string_value (rs_const_avp *vp)
{
  if (!rs_avp_is_string (vp))
    return NULL;

  return vp->vp_strvalue;
}

int
rs_avp_string_set (rs_avp *vp, const char *str)
{
  int err;

  if (vp == NULL)
    return RSE_INVAL;
  if (!rs_avp_is_string (vp))
    return RSE_ATTR_INVALID;

  err = nr_vp_set_data (vp, str, strlen (str));
  return RS_ERR(err);
}

uint32_t
rs_avp_integer_value (rs_const_avp *vp)
{
  if (!rs_avp_is_integer (vp))
    return 0;
  return vp->vp_integer;
}

int
rs_avp_integer_set (rs_avp *vp, uint32_t val)
{
  int err;

  if (vp == NULL)
    return RSE_INVAL;
  if (!rs_avp_is_integer (vp))
    return RSE_ATTR_INVALID;

  err = nr_vp_set_data (vp, &val, sizeof (val));
  return RS_ERR(err);
}

uint32_t
rs_avp_ipaddr_value (rs_const_avp *vp)
{
  if (!rs_avp_is_ipaddr (vp))
    return 0;
  return vp->vp_ipaddr;
}

int
rs_avp_ipaddr_set (rs_avp *vp, struct in_addr in)
{
  int err;

  if (vp == NULL)
    return RSE_INVAL;
  if (!rs_avp_is_ipaddr (vp))
    return RSE_ATTR_INVALID;

  err = nr_vp_set_data (vp, &in, sizeof (in));
  return RS_ERR(err);
}

time_t
rs_avp_date_value (rs_const_avp *vp)
{
  if (!rs_avp_is_date (vp))
    return 0;
  return vp->vp_date;
}

int
rs_avp_date_set (rs_avp *vp, time_t date)
{
  uint32_t date32;
  int err;

  if (vp == NULL)
    return RSE_INVAL;
  if (!rs_avp_is_date (vp))
    return RSE_ATTR_INVALID;
  if (date > 0xFFFFFFFF)
    return RSE_ATTR_INVALID;

  date32 = (uint32_t)date;
  err = nr_vp_set_data (vp, &date32, sizeof (date32));

  return RS_ERR(err);
}

const unsigned char *
rs_avp_octets_value_const_ptr (rs_const_avp *vp)
{
  return rs_avp_octets_value_ptr ((rs_avp *)vp);
}

unsigned char *
rs_avp_octets_value_ptr (rs_avp *vp)
{
  if (vp == NULL)
    return NULL;

#ifdef RS_TYPE_TLV
  if (rs_avp_is_tlv (vp))
    return vp->vp_tlv;
#endif

  return vp->vp_octets;
}

int
rs_avp_octets_value_byref (rs_avp *vp,
			   unsigned char **p,
			   size_t *len)
{
  if (vp == NULL)
    return RSE_INVAL;

  *len = vp->length;
  *p = (unsigned char *)rs_avp_octets_value_ptr (vp);

  return RSE_OK;
}

int
rs_avp_octets_value (rs_const_avp *vp,
		     unsigned char *buf,
		     size_t *len)
{
  if (vp == NULL)
    return RSE_INVAL;

  if (vp->length > *len) {
    *len = vp->length;
    return RSE_ATTR_TOO_SMALL;
  }

  *len = vp->length;

#ifdef RS_TYPE_TLV
  if (rs_avp_is_tlv (vp))
    memcpy (buf, vp->vp_tlv, vp->length);
  else
#endif
    memcpy (buf, vp->vp_octets, vp->length);

  return RSE_OK;
}

int
rs_avp_fragmented_value (rs_const_avp *vps,
		         unsigned char *buf,
		         size_t *len)
{
  size_t total_len = 0;
  unsigned char *p;
  rs_const_avp *vp;

  if (vps == NULL)
    return RSE_INVAL;

  if (!rs_avp_is_octets (vps) &&
      !rs_avp_is_string (vps))
    return RSE_ATTR_INVALID;

  for (vp = vps;
       vp != NULL;
       vp = rs_avp_find_const (vp->next, vp->da->attr, vp->da->vendor))
    total_len += vp->length;

  if (*len < total_len) {
    *len = total_len;
    return RSE_ATTR_TOO_SMALL;
  }

  for (vp = vps, p = buf;
       vp != NULL;
       vp = rs_avp_find_const (vp->next, vp->da->attr, vp->da->vendor)) {
    memcpy (p, vp->vp_octets, vp->length);
    p += vp->length;
  }

  *len = total_len;

  return RSE_OK;
}

int
rs_avp_octets_set (rs_avp *vp,
		   const unsigned char *buf,
		   size_t len)
{
  int err;

  if (!rs_avp_is_octets (vp))
    return RSE_ATTR_INVALID;

  err = nr_vp_set_data (vp, buf, len);

  return RS_ERR(err);
}

int
rs_avp_ifid_value (rs_const_avp *vp, uint8_t val[8])
{
  if (!rs_avp_is_ifid (vp))
    return RSE_ATTR_INVALID;

  memcpy (val, vp->vp_ifid, 8);

  return RSE_OK;
}

int
rs_avp_ifid_set (rs_avp *vp, const uint8_t val[8])
{
  int err;

  if (!rs_avp_is_ifid (vp))
    return RSE_ATTR_INVALID;

  err = nr_vp_set_data (vp, val, 8);
  return RS_ERR(err);
}

uint8_t
rs_avp_byte_value (rs_const_avp *vp)
{
  if (!rs_avp_is_byte (vp))
    return 0;
  return vp->vp_integer;
}

int
rs_avp_byte_set (rs_avp *vp, uint8_t val)
{
  int err;

  if (!rs_avp_is_byte (vp))
    return RSE_ATTR_INVALID;

  err = nr_vp_set_data (vp, &val, sizeof (val));
  return RS_ERR(err);
}

uint16_t
rs_avp_short_value (rs_const_avp *vp)
{
  if (!rs_avp_is_short (vp))
    return 0;
  return vp->vp_integer;
}

int
rs_avp_short_set (rs_avp *vp, uint16_t val)
{
  int err;

  if (!rs_avp_is_short (vp))
    return RSE_ATTR_INVALID;

  err = nr_vp_set_data (vp, &val, sizeof (val));
  return RS_ERR(err);
}

int
rs_attr_find (const char *name,
              unsigned int *attr,
              unsigned int *vendor)
{
  const DICT_ATTR *da;

  da = nr_dict_attr_byname (name);
  if (da == NULL)
    return RSE_ATTR_UNKNOWN;

  *attr = da->attr;
  *vendor = da->vendor;

  return RSE_OK;
}

int
rs_attr_display_name (unsigned int attr,
                      unsigned int vendor,
                      char *buffer,
                      size_t bufsize,
                      int canonical)
{
  const DICT_ATTR *da = NULL;
  DICT_ATTR da2;
  int err;

  if (!canonical) {
    da = nr_dict_attr_byvalue (attr, vendor);
  }
  if (da == NULL) {
    err = nr_dict_attr_2struct(&da2, attr, vendor,
                               buffer, bufsize);
    if (err < 0)
      return -err;
  } else {
    snprintf(buffer, bufsize, "%s", da->name);
  }

  return RSE_OK;
}

int
rs_attr_parse_name (const char *name,
		    unsigned int *attr,
		    unsigned int *vendor)
{
  const DICT_ATTR *da;

  if (strncmp(name, "Attr-", 5) == 0) {
    char *s = (char *)&name[5];
    unsigned int tmp;

    tmp = strtoul(s, &s, 10);
    if (*s == '.') {
      s++;

      switch (tmp) {
      case PW_VENDOR_SPECIFIC:
	*vendor = strtoul(s, &s, 10);
	if (*s != '.')
	  return RSE_ATTR_BAD_NAME;

	s++;

	*attr = strtoul(s, &s, 10);
	if (*s != '\0')
	  return RSE_ATTR_BAD_NAME;

	break;
      default:
	return RSE_ATTR_BAD_NAME;
      }
    } else {
      *attr = tmp;
      *vendor = 0;
    }
  } else {
    da = nr_dict_attr_byname (name);
    if (da == NULL)
      return RSE_ATTR_UNKNOWN;

    *attr = da->attr;
    *vendor = da->vendor;
  }

  return RSE_OK;
}

size_t
rs_avp_display_value (rs_const_avp *vp,
                      char *buffer,
                      size_t buflen)
{
  return nr_vp_snprintf_value (buffer, buflen, vp);
}

