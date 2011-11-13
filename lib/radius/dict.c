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

#include "client.h"
#include <ctype.h>

/** \file dict.c
 *  \brief Functions for name to number, and number to name mappings.
 */

const DICT_ATTR *nr_dict_attr_byvalue(unsigned int attr, unsigned int vendor)
{
	int start, half, end;

	if (!vendor && (attr > 0) && (attr < 256)) {
		if (nr_dict_attrs[attr].name) {
			return &nr_dict_attrs[attr];
		}
		return NULL;
	}

	if (!vendor) return NULL; /* no "non-protocol" attributes */

	start = 256;		/* first 256 entries are "standard" ones */
	end = nr_dict_num_attrs;

	do {
		half = (start + end) / 2;

		if ((nr_dict_attrs[half].vendor == vendor) &&
		    (nr_dict_attrs[half].attr == attr)) {
			return &nr_dict_attrs[half];
		}

		if ((vendor >= nr_dict_attrs[half].vendor) &&
		    (attr > nr_dict_attrs[half].attr)) {
			start = half + 1;
		} else {
			end = half - 1;
		}

	} while (start <= end);

	return NULL;
}

const DICT_ATTR *nr_dict_attr_byname(const char *name)
{
	int start, half, end;

	start = 1;
	end = nr_dict_num_names;

	if (!name || !*name) return NULL;

	do {
		int rcode;

		half = (start + end) / 2;

		rcode = strcasecmp(name, nr_dict_attr_names[half]->name);
		if (rcode == 0) return nr_dict_attr_names[half];

		if (rcode > 0) {
			start = half + 1;
		} else {
			end = half - 1;
		}


	} while (start <= end);

	return NULL;
}

int nr_dict_attr_2struct(DICT_ATTR *da, unsigned int attr, unsigned int vendor,
			 char *buffer, size_t bufsize)
{
	if (!da || !buffer) return -RSE_INVAL;

	if (!vendor) {
		if (attr > 256) return -RSE_INVAL;

	} else if (vendor > (1 << 24)) {
		return -RSE_INVAL;
	}

	memset(da, 0, sizeof(*da));
	da->attr = attr;
	da->flags.unknown = 1;
	da->type = RS_TYPE_OCTETS;
	da->vendor = vendor;

	if (da->vendor) {
		snprintf(buffer, bufsize, "Attr-26.%u.%u",
			 vendor, attr);
	} else {
		snprintf(buffer, bufsize, "Attr-%u", attr);
	}
	da->name = buffer;

	return 0;
}


const DICT_VALUE *nr_dict_value_byattr(UNUSED unsigned int attr,
				 UNUSED unsigned int vendor,
				 UNUSED int value)
{
	return NULL;
}

const DICT_VALUE *nr_dict_value_byname(UNUSED unsigned int attr,
				 UNUSED unsigned int vendor,
				 UNUSED const char *name)
{
	return NULL;
}

int nr_dict_vendor_byname(const char *name)
{
	const DICT_VENDOR *dv;

	if (!name || !*name) return 0;

	/*
	 *	O(n) lookup.
	 */
	for (dv = &nr_dict_vendors[0]; dv->name != NULL; dv++) {
		if (strcasecmp(dv->name, name) == 0) return dv->vendor;
	}

	return 0;
}

const DICT_VENDOR *nr_dict_vendor_byvalue(unsigned int vendor)
{
	const DICT_VENDOR *dv;

	/*
	 *	O(n) lookup.
	 */
	for (dv = &nr_dict_vendors[0]; dv->name != NULL; dv++) {
		if (dv->vendor == vendor) return dv;
	}

	return NULL;
}
