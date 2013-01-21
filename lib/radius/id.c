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

#include	"client.h"

#ifdef HAVE_UNISTD_H
#include	<unistd.h>
#endif

/** \file id.c
 *  \brief Handling of ID allocation / freeing
 *
 */

static int find_id(nr_server_t *s)
{
	int i;
	uint32_t lvalue;

	if ((s->used < 0) || (s->used > 256)) return -RSE_INTERNAL;

	/*
	 *	Ensure that the ID allocation is random.
	 */
	lvalue = nr_rand();

	for (i = 0; i < 256; i++) {
		int offset = (i + lvalue) & 0xff;

		if (!s->ids[offset]) return offset;
	}

	nr_strerror_printf("Out of IDs for server");
	return -1;
}

int nr_server_id_alloc(nr_server_t *s, RADIUS_PACKET *packet)
{
	int new_id;

	if (!s || !packet) return -RSE_INVAL;

	new_id = find_id(s);
	if (new_id < 0) return -new_id;

	s->ids[new_id] = packet;
	s->used++;
	packet->sockfd = s->sockfd;
	packet->code = s->code;
	packet->src = s->src;
	packet->dst = s->dst;
	packet->id = new_id;

	return 0;
}

int nr_server_id_free(nr_server_t *s, RADIUS_PACKET *packet)
{
	if (!s || !packet) return -RSE_INVAL;

	if ((packet->id < 0) || (packet->id > 255) || !s->ids[packet->id]) {
		return -RSE_INVAL;
	}

	if (s->ids[packet->id] != packet) return -RSE_INTERNAL;

	s->ids[packet->id] = NULL;
	s->used--;
	packet->sockfd = -1;

	return 0;
}

int nr_server_id_realloc(nr_server_t *s, RADIUS_PACKET *packet)
{
	int new_id;

	if (!s || !packet) return -RSE_INVAL;

	if ((packet->id < 0) || (packet->id > 255) || !s->ids[packet->id]) {
		return -RSE_INVAL;
	}

	if (s->ids[packet->id] != packet) return -RSE_INTERNAL;

	new_id = find_id(s);
	if (new_id < 0) return new_id;

	s->ids[packet->id] = NULL;
	packet->id = new_id;
	s->ids[packet->id] = packet;

	return 0;
}


int nr_server_init(nr_server_t *s, int code, const char *secret)
{
	if (!s || !secret || !*secret ||
	    (code == 0) || (code > RS_MAX_PACKET_CODE)) {
		return -RSE_INVAL;
	}

	memset(s, 0, sizeof(*s));

	s->sockfd = -1;
	s->code = code;
	s->secret = secret;
	s->sizeof_secret = strlen(secret);
	s->src.ss_family = AF_UNSPEC;
	s->dst.ss_family = AF_UNSPEC;

	return 0;
}


int nr_server_close(const nr_server_t *s)
{
	if (!s) return -RSE_INVAL;

	if (s->used > 0) return -RSE_INUSE;

	if (s->sockfd >= 0) evutil_closesocket(s->sockfd);

	return 0;
}

int nr_server_packet_alloc(const nr_server_t *s, RADIUS_PACKET **packet_p)
{
	int rcode;
	RADIUS_PACKET *packet;

	if (!packet_p) return -RSE_INVAL;

	packet = malloc(sizeof(*packet) + RS_MAX_PACKET_LEN);
	if (!packet) return -RSE_NOMEM;

	memset(packet, 0, sizeof(*packet));

	if (!s) {
		packet->data = (uint8_t *)(packet + 1);
		packet->sizeof_data = RS_MAX_PACKET_LEN;

		*packet_p = packet;
		return 0;
	}

	rcode = nr_packet_init(packet, NULL, s->secret, s->code,
			       (uint8_t *)(packet + 1), RS_MAX_PACKET_LEN);
	if (rcode < 0) {
		free(packet);
		return rcode;
	}

	*packet_p = packet;
	return 0;
}
