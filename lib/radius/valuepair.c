/*
Copyright (c) 2011, Network RADIUS SARL
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** \file valuepair.c
 *  \brief Functions to manipulate C structure versions of RADIUS attributes.
 */

#include "client.h"

void nr_vp_free(VALUE_PAIR **head)
{
	VALUE_PAIR	*next, *vp;

	for (vp = *head; vp != NULL; vp = next) {
		next = vp->next;
		if (vp->da->flags.encrypt) {
			memset(vp, 0, sizeof(vp));
		}
		free(vp);
	}

	*head = NULL;
}


VALUE_PAIR *nr_vp_init(VALUE_PAIR *vp, const DICT_ATTR *da)
{
	memset(vp, 0, sizeof(*vp));
	
	vp->da = da;
	vp->length = da->flags.length;

	return vp;
}


VALUE_PAIR *nr_vp_alloc(const DICT_ATTR *da)
{
	VALUE_PAIR *vp = NULL;

	if (!da) {
		nr_strerror_printf("Unknown attribute");
		return NULL;
	}

	vp = malloc(sizeof(*vp));
	if (!vp) {
		nr_strerror_printf("Out of memory");
		return NULL;
	}

	return nr_vp_init(vp, da);
}

VALUE_PAIR *nr_vp_alloc_raw(unsigned int attr, unsigned int vendor)
{
	VALUE_PAIR *vp = NULL;
	DICT_ATTR *da;

	vp = malloc(sizeof(*vp) + sizeof(*da) + 64);
	if (!vp) {
		nr_strerror_printf("Out of memory");
		return NULL;
	}
	memset(vp, 0, sizeof(*vp));

	da = (DICT_ATTR *) (vp + 1);

	if (nr_dict_attr_2struct(da, attr, vendor, (char *) (da + 1), 64) < 0) {
		free(vp);
		return NULL;
	}

	vp->da = da;

	return vp;
}

int nr_vp_set_data(VALUE_PAIR *vp, const void *data, size_t sizeof_data)
{
	int rcode = 1;		/* OK */

	if (!vp || !data || (sizeof_data == 0)) return -RSE_INVAL;

	switch (vp->da->type) {
	case RS_TYPE_BYTE:
		vp->vp_integer = *(const uint8_t *) data;
		break;
		
	case RS_TYPE_SHORT:
		vp->vp_integer = *(const uint16_t *) data;
		break;
		
	case RS_TYPE_INTEGER:
	case RS_TYPE_DATE:
	case RS_TYPE_IPADDR:
		vp->vp_integer = *(const uint32_t *) data;
		break;
		
	case RS_TYPE_STRING:
		if (sizeof_data >= sizeof(vp->vp_strvalue)) {
			sizeof_data = sizeof(vp->vp_strvalue) - 1;
			rcode = 0; /* truncated */
		}

		memcpy(vp->vp_strvalue, (const char *) data, sizeof_data);
		vp->vp_strvalue[sizeof_data + 1] = '\0';
		vp->length = sizeof_data;
		break;
		
	case RS_TYPE_OCTETS:
		if (sizeof_data > sizeof(vp->vp_octets)) {
			sizeof_data = sizeof(vp->vp_octets);
			rcode = 0; /* truncated */
		}
		memcpy(vp->vp_octets, data, sizeof_data);
		vp->length = sizeof_data;
		break;
		
	default:
		return -RSE_ATTR_TYPE_UNKNOWN;
	}

	return rcode;
}

VALUE_PAIR *nr_vp_create(int attr, int vendor, const void *data, size_t data_len)
{
	const DICT_ATTR	*da;
	VALUE_PAIR *vp;

	da = nr_dict_attr_byvalue(attr, vendor);
	if (!da) return NULL;

	vp = nr_vp_alloc(da);
	if (!vp) return NULL;
	
	if (nr_vp_set_data(vp, data, data_len) < 0) {
		nr_vp_free(&vp);
		return NULL;
	}

	return vp;
}

void nr_vps_append(VALUE_PAIR **head, VALUE_PAIR *tail)
{
	if (!tail) return;

	while (*head) {
		head = &((*head)->next);
	}

	*head = tail;
}

VALUE_PAIR *nr_vps_find(VALUE_PAIR *head,
		     unsigned int attr, unsigned int vendor)
{
	while (head) {
		if ((head->da->attr == attr) &&
		    (head->da->vendor == vendor)) return head;
		head = head->next;
	}

	return NULL;
}
