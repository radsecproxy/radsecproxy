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

#include <networkradius-devel/client.h>
#include <string.h>
#ifdef NR_TYPE_IPV6ADDR
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
	if ((packet->flags & NR_PACKET_SIGNED) == 0) printf("\t\tWARNING: nr_packet_sign() was not called!\n");

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
	case NR_TYPE_STRING:
		/*
		 *	FIXME: escape backslash && quotes!
		 */
		len = snprintf(p, buflen, "\"%s\"", vp->vp_strvalue);
		break;

	case NR_TYPE_DATE:
	case NR_TYPE_INTEGER:
	case NR_TYPE_SHORT:
	case NR_TYPE_BYTE:
		len = snprintf(p, buflen, "%u", vp->vp_integer);
		break;

	case NR_TYPE_IPADDR:
		len = snprintf(p, buflen, "%u.%u.%u.%u",
			       (vp->vp_ipaddr >> 24) & 0xff,
			       (vp->vp_ipaddr >> 16) & 0xff,
			       (vp->vp_ipaddr >> 8) & 0xff,
			       vp->vp_ipaddr & 0xff);
		break;

#ifdef NR_TYPE_IPV6ADDR
	case NR_TYPE_IPV6ADDR:
		if (!inet_ntop(AF_INET6, &vp->vp_ipv6addr, buffer, buflen)) {
			return -NR_ERR_SYSTEM;
		}
		break;
#endif

#ifdef NR_TYPE_IFID
	case NR_TYPE_IFID:
		len = snprintf(p, buflen, "%02x%02x%02x%02x%02x%02x%02x%02x",
			       vp->vp_ifid[0], vp->vp_ifid[1],
			       vp->vp_ifid[2], vp->vp_ifid[3],
			       vp->vp_ifid[4], vp->vp_ifid[5],
			       vp->vp_ifid[6], vp->vp_ifid[7]);
		break;
#endif

	case NR_TYPE_OCTETS:
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

const char *nr_strerror(int error)
{
	if (error == 0) return nr_strerror_buffer;

	if (error < 0) error = -error;

	switch (error) {
	default: return "Unknown error";
	case NR_ERR_SYSTEM: return strerror(errno);

	case NR_ERR_INVALID_ARG: return "Invalid argument";
	case NR_ERR_PACKET_TOO_SMALL: return "Packet is too small";
	case NR_ERR_PACKET_TOO_LARGE: return "Packet is too large";
	case NR_ERR_ATTR_OVERFLOW: return "Attribute overflows packet";
	case NR_ERR_ATTR_TOO_SMALL: return "Attribute is too small";
	case NR_ERR_ATTR_TOO_LARGE: return "Attribute is too large";
	case NR_ERR_ATTR_UNKNOWN: return "Unknown attribute";
	case NR_ERR_ATTR_BAD_NAME: return "Invalid name for attribute";
	case NR_ERR_ATTR_VALUE_MALFORMED: return "Invalid value for attribute";
	case NR_ERR_ATTR_INVALID: return "Invalid attribute";
	case NR_ERR_TOO_MANY_ATTRS: return "Too many attributes in the packet";
	case NR_ERR_ATTR_TYPE_UNKNOWN: return "Attribute type unknown";
	case NR_ERR_MSG_AUTH_LEN: return "Invalid Message-Authenticator";
	case NR_ERR_MSG_AUTH_WRONG: return "Incorrect Message-Authenticator";
	case NR_ERR_REQUEST_REQUIRED: return "Request is required";
	case NR_ERR_REQUEST_CODE_INVALID: return "Invalid request code";
	case NR_ERR_AUTH_VECTOR_WRONG: return "Incorrect Request Authenticator";
	case NR_ERR_RESPONSE_CODE_INVALID: return "Response code is unsupported";
	case NR_ERR_RESPONSE_ID_INVALID: return "Response ID is invalid";
	case NR_ERR_RESPONSE_SRC_INVALID: return "Response from the wrong src ip/port";
	case NR_ERR_NO_PACKET_DATA: return "Cannot encode the packet";
	case NR_ERR_VENDOR_UNKNOWN: return "Vendor is unknown";
	case NR_ERR_INTERNAL_FAILURE: return "Internal failure";
	case NR_ERR_UNSUPPORTED: return "Unsupported feature";
	case NR_ERR_NO_MEM: return "Out of memory";
	case NR_ERR_IN_USE: return "Resource is in use";
		
	}
}
