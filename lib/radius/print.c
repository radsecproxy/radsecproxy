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

/** \file print.c
 *  \brief Functions to print things.
 */

#include "client.h"
#include <string.h>
#ifdef RS_TYPE_IPV6ADDR
#include <arpa/inet.h>
#endif

#ifndef NDEBUG
void nr_packet_print_hex(RADIUS_PACKET *packet)
{
	int i;

	if (!packet->data) return;

	printf("  Code:\t\t%u\n", packet->data[0]);
	printf("  Id:\t\t%u\n", packet->data[1]);
	printf("  Length:\t%u\n", ((packet->data[2] << 8) |
				   (packet->data[3])));
	printf("  Vector:\t");
	for (i = 4; i < 20; i++) {
		printf("%02x", packet->data[i]);
	}
	printf("\n");
	if ((packet->flags & RS_PACKET_SIGNED) == 0) printf("\t\tWARNING: nr_packet_sign() was not called!\n");

	if (packet->length > 20) {
		int total;
		const uint8_t *ptr;
		printf("  Data:");

		total = packet->length - 20;
		ptr = packet->data + 20;

		while (total > 0) {
			int attrlen;

			printf("\t\t");
			if (total < 2) { /* too short */
				printf("%02x\n", *ptr);
				break;
			}

			if (ptr[1] > total) { /* too long */
				for (i = 0; i < total; i++) {
					printf("%02x ", ptr[i]);
				}
				break;
			}

			printf("%02x  %02x  ", ptr[0], ptr[1]);
			attrlen = ptr[1] - 2;
			ptr += 2;
			total -= 2;

			for (i = 0; i < attrlen; i++) {
				if ((i > 0) && ((i & 0x0f) == 0x00))
					printf("\t\t\t");
				printf("%02x ", ptr[i]);
				if ((i & 0x0f) == 0x0f) printf("\n");
			}

			if (!attrlen || ((attrlen & 0x0f) != 0x00)) printf("\n");

			ptr += attrlen;
			total -= attrlen;
		}
	}
	printf("\n");
	fflush(stdout);
}
#endif

size_t nr_vp_snprintf_value(char *buffer, size_t buflen, const VALUE_PAIR *vp)
{
	size_t i, len;
	char *p = buffer;

	switch (vp->da->type) {
	case RS_TYPE_STRING:
		/*
		 *	FIXME: escape backslash && quotes!
		 */
		len = snprintf(p, buflen, "%s", vp->vp_strvalue);
		break;

	case RS_TYPE_DATE:
	case RS_TYPE_INTEGER:
	case RS_TYPE_SHORT:
	case RS_TYPE_BYTE:
		len = snprintf(p, buflen, "%u", vp->vp_integer);
		break;

	case RS_TYPE_IPADDR:
		len = snprintf(p, buflen, "%u.%u.%u.%u",
			       (vp->vp_ipaddr >> 24) & 0xff,
			       (vp->vp_ipaddr >> 16) & 0xff,
			       (vp->vp_ipaddr >> 8) & 0xff,
			       vp->vp_ipaddr & 0xff);
		break;

#ifdef RS_TYPE_IPV6ADDR
	case RS_TYPE_IPV6ADDR:
		if (!inet_ntop(AF_INET6, &vp->vp_ipv6addr, buffer, buflen)) {
			return -RSE_SYSTEM;
		}
		break;
#endif

#ifdef RS_TYPE_IFID
	case RS_TYPE_IFID:
		len = snprintf(p, buflen, "%02x%02x%02x%02x%02x%02x%02x%02x",
			       vp->vp_ifid[0], vp->vp_ifid[1],
			       vp->vp_ifid[2], vp->vp_ifid[3],
			       vp->vp_ifid[4], vp->vp_ifid[5],
			       vp->vp_ifid[6], vp->vp_ifid[7]);
		break;
#endif

	case RS_TYPE_OCTETS:
		len = snprintf(p, buflen, "0x");
		if (len >= buflen) return 0;

		p += len;
		buflen -= len;

		for (i = 0; i < vp->length; i++) {
			len = snprintf(p, buflen, "%02x", vp->vp_octets[i]);
			if (len >= buflen) return 0;
			
			p += len;
			buflen -= len;
		}
		len = 0;
		break;

	default:
		len = 0;
		break;
	}

	if (len >= buflen) return 0;

	p += len;
	buflen -= len;

	return p - buffer;
}

size_t nr_vp_snprintf(char *buffer, size_t buflen, const VALUE_PAIR *vp)
{
	size_t len;
	char *p = buffer;

	len = snprintf(p, buflen, "%s = ", vp->da->name);
	if (len >= buflen) return 0;

	p += len;
	buflen -= len;

	len = nr_vp_snprintf_value(p, buflen, vp);
	if (len == 0) return 0;

	if (len >= buflen) return 0;

	p += len;

	return p - buffer;
}

#ifndef NDEBUG
void nr_vp_fprintf_list(FILE *fp, const VALUE_PAIR *vps)
{
	const VALUE_PAIR *vp;
	char buffer[1024];

	for (vp = vps; vp != NULL; vp = vp->next) {
		nr_vp_snprintf(buffer, sizeof(buffer), vp);
		fprintf(fp, "\t%s\n", buffer);
	}
}
#endif

/** \cond PRIVATE */
#define NR_STRERROR_BUFSIZE (1024)
static char nr_strerror_buffer[NR_STRERROR_BUFSIZE];

void nr_strerror_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(nr_strerror_buffer, sizeof(nr_strerror_buffer), fmt, ap);
	va_end(ap);

	fprintf(stderr, "ERROR: %s\n", nr_strerror_buffer);
}
/** \endcond */

