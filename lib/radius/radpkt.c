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

/** \file packet.c
 *  \brief Encoding and decoding packets
 */

#include	"client.h"

#if RS_MAX_PACKET_LEN < 64
#error RS_MAX_PACKET_LEN is too small.  It should be at least 64.
#endif

#if RS_MAX_PACKET_LEN > 16384
#error RS_MAX_PACKET_LEN is too large.  It should be smaller than 16K.
#endif

const char *nr_packet_codes[RS_MAX_PACKET_CODE + 1] = {
  NULL,
  "Access-Request",
  "Access-Accept",
  "Access-Reject",
  "Accounting-Request",
  "Accounting-Response",
  NULL, NULL, NULL, NULL, NULL,
  "Access-Challenge",
  "Status-Server",		/* 12 */
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 19 */
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 20..29 */
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 30..39 */
  "Disconnect-Request",
  "Disconnect-ACK",
  "Disconnect-NAK",
  "CoA-Request",
  "CoA-ACK",
  "CoA-NAK"
};


static uint64_t allowed_responses[RS_MAX_PACKET_CODE + 1] = {
	0,
	(1 << PW_ACCESS_ACCEPT) | (1 << PW_ACCESS_REJECT) | (1 << PW_ACCESS_CHALLENGE),
	0, 0,
	1 << PW_ACCOUNTING_RESPONSE,
	0,
	0, 0, 0, 0, 0,
	0,
	(1 << PW_ACCESS_ACCEPT) | (1 << PW_ACCESS_REJECT) | (1 << PW_ACCESS_CHALLENGE) | (1 << PW_ACCOUNTING_RESPONSE),
	0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 20..29 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 30..39 */
	(((uint64_t) 1) << PW_DISCONNECT_ACK) | (((uint64_t) 1) << PW_DISCONNECT_NAK),
	0,
	0,
	(((uint64_t) 1) << PW_COA_ACK) | (((uint64_t) 1) << PW_COA_NAK),
	0,
	0
};


int nr_packet_ok_raw(const uint8_t *data, size_t sizeof_data)
{
	size_t packet_len;
	const uint8_t *attr, *end;

	if (!data || (sizeof_data < 20)) {
		nr_debug_error("Invalid argument");
		return -RSE_INVAL;
	}

	packet_len = (data[2] << 8) | data[3];
	if (packet_len < 20) {
		nr_debug_error("Packet length is too small");
		return -RSE_PACKET_TOO_SMALL;
	}

	if (packet_len > sizeof_data) {
		nr_debug_error("Packet length overflows received data");
		return -RSE_PACKET_TOO_LARGE;
	}

	/*
	 *	If we receive 100 bytes, and the header says it's 20 bytes,
	 *	then it's 20 bytes.
	 */
	end = data + packet_len;

	for (attr = data + 20; attr < end; attr += attr[1]) {
		if ((attr + 2) > end) {
			nr_debug_error("Attribute overflows packet");
			return -RSE_ATTR_OVERFLOW;
		}

		if (attr[1] < 2) {
			nr_debug_error("Attribute length is too small");
			return -RSE_ATTR_TOO_SMALL;
		}

		if ((attr + attr[1]) > end) {
			nr_debug_error("Attribute length is too large");
			return -RSE_ATTR_TOO_LARGE;
		}
	}

	return 0;
}

int nr_packet_ok(RADIUS_PACKET *packet)
{
	int rcode;

	if (!packet) return -RSE_INVAL;

	if ((packet->flags & RS_PACKET_OK) != 0) return 0;

	rcode = nr_packet_ok_raw(packet->data, packet->length);
	if (rcode < 0) return rcode;

	packet->flags |= RS_PACKET_OK;
	return 0;
}


/*
 *	Comparison function that is time-independent.  Using "memcmp"
 *	would satisfy the "comparison" part.  However, it would also
 *	leak information about *which* bytes are wrong.  Attackers
 *	could use that leak to create a "correct" RADIUS packet which
 *	will be accepted by the client and/or server.
 */
static int digest_cmp(const uint8_t *a, const uint8_t *b, size_t length)
{
	int result = 0;
	size_t i;

	for (i = 0; i < length; i++) {
		result |= (a[i] ^ b[i]);
	}

	return result;
}


#ifdef PW_MESSAGE_AUTHENTICATOR
static int msg_auth_ok(const RADIUS_PACKET *original,
		       uint8_t *ma,
		       uint8_t *data, size_t length)
{
	uint8_t	packet_vector[sizeof(original->vector)];
	uint8_t	msg_auth_vector[sizeof(original->vector)];
	uint8_t calc_auth_vector[sizeof(original->vector)];
	
	if (ma[1] != 18) {
		nr_debug_error("Message-Authenticator has invalid length");
		return -RSE_MSG_AUTH_LEN;
	}

	memcpy(packet_vector, data + 4, sizeof(packet_vector));
	memcpy(msg_auth_vector, ma + 2, sizeof(msg_auth_vector));
	memset(ma + 2, 0, sizeof(msg_auth_vector));

	switch (data[0]) {
	default:
		break;
		
	case PW_ACCOUNTING_REQUEST:
	case PW_ACCOUNTING_RESPONSE:
	case PW_DISCONNECT_REQUEST:
	case PW_DISCONNECT_ACK:
	case PW_DISCONNECT_NAK:
	case PW_COA_REQUEST:
	case PW_COA_ACK:
	case PW_COA_NAK:
		memset(data + 4, 0, sizeof(packet_vector));
		break;
		
	case PW_ACCESS_ACCEPT:
	case PW_ACCESS_REJECT:
	case PW_ACCESS_CHALLENGE:
		if (!original) {
			nr_debug_error("Cannot validate response without request");
			return -RSE_REQUEST_REQUIRED;
		}
		memcpy(data + 4, original->vector, sizeof(original->vector));
		break;
	}
	
	nr_hmac_md5(data, length,
		    (const uint8_t *) original->secret, original->sizeof_secret,
		    calc_auth_vector);

	memcpy(ma + 2, msg_auth_vector, sizeof(msg_auth_vector));
	memcpy(data + 4, packet_vector, sizeof(packet_vector));

	if (digest_cmp(calc_auth_vector, msg_auth_vector,
		       sizeof(calc_auth_vector)) != 0) {
		nr_debug_error("Invalid Message-Authenticator");
		return -RSE_MSG_AUTH_WRONG;
	}

	return 1;
}
#endif

/*
 *	The caller ensures that the packet codes are as expected.
 */
static int packet_auth_ok(const RADIUS_PACKET *original,
			  uint8_t *data, size_t length)
{
	uint8_t packet_vector[sizeof(original->vector)];
	uint8_t calc_digest[sizeof(original->vector)];
	RS_MD5_CTX ctx;

	if ((data[0] == PW_ACCESS_REQUEST) ||
	    (data[0] == PW_STATUS_SERVER)) return 1;

	memcpy(packet_vector, data + 4, sizeof(packet_vector));

	if (!original) {
		memset(data + 4, 0, sizeof(packet_vector));
	} else {
		memcpy(data + 4, original->vector, sizeof(original->vector));
	}

	RS_MD5Init(&ctx);
	RS_MD5Update(&ctx, data, length);
	RS_MD5Update(&ctx, (const unsigned char *)original->secret, original->sizeof_secret);
	RS_MD5Final(calc_digest, &ctx);

	memcpy(data + 4, packet_vector, sizeof(packet_vector));

	if (digest_cmp(calc_digest, packet_vector,
		       sizeof(packet_vector)) != 0) {
		nr_debug_error("Invalid authentication vector");
		return -RSE_AUTH_VECTOR_WRONG;
	}

	return 0;
}


int nr_packet_verify(RADIUS_PACKET *packet, const RADIUS_PACKET *original)
{
	int rcode;
	uint8_t *attr;
#ifdef PW_MESSAGE_AUTHENTICATOR
	const uint8_t *end;
#endif

	if (!packet || !packet->data || !packet->secret) {
		nr_debug_error("Invalid argument");
		return -RSE_INVAL;
	}

	if ((packet->flags & RS_PACKET_VERIFIED) != 0) return 0;

	/*
	 *	Packet isn't well formed.  Ignore it.
	 */
	rcode = nr_packet_ok(packet);
	if (rcode < 0) return rcode;

	/*
	 *	Get rid of improper packets as early as possible.
	 */
	if (original) {
		uint64_t mask;

		if (original->code > RS_MAX_PACKET_CODE) {
			nr_debug_error("Invalid original code %u",
					   original->code);
			return -RSE_INVALID_REQUEST_CODE;
		}

		if (packet->data[1] != original->id) {
			nr_debug_error("Ignoring response with wrong ID %u",
					   packet->data[1]);
			return -RSE_INVALID_RESPONSE_CODE;
		}

		mask = 1;
		mask <<= packet->data[0];

		if ((allowed_responses[original->code] & mask) == 0) {
			nr_debug_error("Ignoring response with wrong code %u",
					   packet->data[0]);
			return -RSE_INVALID_RESPONSE_CODE;
		}

		if ((memcmp(&packet->src, &original->dst, sizeof(packet->src)) != 0) &&
		    (evutil_sockaddr_cmp((struct sockaddr *)&packet->src, (struct sockaddr *)&original->dst, 1) != 0)) {
			nr_debug_error("Ignoring response from wrong IP/port");
			return -RSE_INVALID_RESPONSE_SRC;
		}

	} else if (allowed_responses[packet->data[0]] != 0) {
		nr_debug_error("Ignoring response without original");
		return -RSE_INVALID_RESPONSE_CODE;
	}

#ifdef PW_MESSAGE_AUTHENTICATOR
	end = packet->data + packet->length;

	/*
	 *	Note that the packet MUST be well-formed here.
	 */
	for (attr = packet->data + 20; attr < end; attr += attr[1]) {
		if (attr[0] == PW_MESSAGE_AUTHENTICATOR) {
			rcode = msg_auth_ok(original, attr,
					    packet->data, packet->length);
			if (rcode < 0) return rcode;
		}
	}
#endif

	/*
	 *	Verify the packet authenticator.
	 */
	rcode = packet_auth_ok(original, packet->data, packet->length);
	if (rcode < 0) return rcode;

	packet->flags |= RS_PACKET_VERIFIED;

	return 0;
}


int nr_packet_decode(RADIUS_PACKET *packet, const RADIUS_PACKET *original)
{
	int		rcode, num_attributes;
	uint8_t		*data, *attr;
	const uint8_t	*end;
	VALUE_PAIR	**tail, *vp;

	if (!packet) return -RSE_INVAL;

	if ((packet->flags & RS_PACKET_DECODED) != 0) return 0;
      
	rcode = nr_packet_ok(packet);
	if (rcode < 0) return rcode;

	data = packet->data;
	end = data + packet->length;
	tail = &packet->vps;
	num_attributes = 0;

	/*
	 *	Loop over the packet, converting attrs to VPs.
	 */
	for (attr = data + 20; attr < end; attr += attr[1]) {
		rcode = nr_attr2vp(packet, original,
				    attr, end - attr, &vp);
		if (rcode < 0) {
			nr_vp_free(&packet->vps);
			return -rcode;
		}

		*tail = vp;
		while (vp) {
			num_attributes++;
			tail = &(vp->next);
			vp = vp->next;
		}

		if (num_attributes > RS_MAX_ATTRIBUTES) {
			nr_debug_error("Too many attributes");
			nr_vp_free(&packet->vps);
			return -RSE_TOO_MANY_ATTRS;
		}
	}

	packet->code = data[0];
	packet->id = data[1];
	memcpy(packet->vector, data + 4, sizeof(packet->vector));

	packet->flags |= RS_PACKET_DECODED;

	return 0;
}


int nr_packet_sign(RADIUS_PACKET *packet, const RADIUS_PACKET *original)
{
#ifdef PW_MESSAGE_AUTHENTICATOR
	size_t ma = 0;
	const uint8_t *attr, *end;
#endif

	if ((packet->flags & RS_PACKET_SIGNED) != 0) return 0;

	if ((packet->flags & RS_PACKET_ENCODED) == 0) {
		int rcode;

		rcode = nr_packet_encode(packet, original);
		if (rcode < 0) return rcode;
	}

	if ((packet->code == PW_ACCESS_ACCEPT) ||
	    (packet->code == PW_ACCESS_CHALLENGE) ||
	    (packet->code == PW_ACCESS_REJECT)) {
#ifdef PW_MESSAGE_AUTHENTICATOR
		if (!original) {
			nr_debug_error("Original packet is required to create the  Message-Authenticator");
			return -RSE_REQUEST_REQUIRED;
		}
#endif
		
		memcpy(packet->data + 4, original->vector,
		       sizeof(original->vector));
	} else {
		memcpy(packet->data + 4, packet->vector,
		       sizeof(packet->vector));
	}

#ifdef PW_MESSAGE_AUTHENTICATOR
	end = packet->data + packet->length;

	for (attr = packet->data + 20; attr < end; attr += attr[1]) {
		if (attr[0] == PW_MESSAGE_AUTHENTICATOR) {
			ma = (attr - packet->data);
			break;
		}
	}

	/*
	 *	Force all Access-Request packets to have a
	 *	Message-Authenticator.
	 */
	if (!ma && ((packet->length + 18) <= packet->sizeof_data) &&
	    ((packet->code == PW_ACCESS_REQUEST) ||
	     (packet->code == PW_STATUS_SERVER))) {
		ma = packet->length;

		packet->data[ma]= PW_MESSAGE_AUTHENTICATOR;
		packet->data[ma + 1] = 18;
		memset(&packet->data[ma + 2], 0, 16);
		packet->length += 18;
	}

	/*
	 *	Reset the length.
	 */
	packet->data[2] = (packet->length >> 8) & 0xff;
	packet->data[3] = packet->length & 0xff;

	/*
	 *	Sign the Message-Authenticator && packet.
	 */
	if (ma) {
		nr_hmac_md5(packet->data, packet->length,
			    (const uint8_t *) packet->secret, packet->sizeof_secret,
			    packet->data + ma + 2);
	}
#endif

	/*
	 *	Calculate the signature.
	 */
	if (!((packet->code == PW_ACCESS_REQUEST) ||
	      (packet->code == PW_STATUS_SERVER))) {
		RS_MD5_CTX	ctx;

		RS_MD5Init(&ctx);
		RS_MD5Update(&ctx, packet->data, packet->length);
		RS_MD5Update(&ctx, (const unsigned char *)packet->secret, packet->sizeof_secret);
		RS_MD5Final(packet->vector, &ctx);
	}

	memcpy(packet->data + 4, packet->vector, sizeof(packet->vector));

	packet->attempts = 0;
	packet->flags |= RS_PACKET_SIGNED;

	return 0;
}


static int can_encode_packet(RADIUS_PACKET *packet,
			     const RADIUS_PACKET *original)
{
	if ((packet->code == 0) ||
	    (packet->code > RS_MAX_PACKET_CODE) ||
	    (original && (original->code > RS_MAX_PACKET_CODE))) {
		nr_debug_error("Cannot send unknown packet code");
		return -RSE_INVALID_REQUEST_CODE;
	}

	if (!nr_packet_codes[packet->code]) {
		nr_debug_error("Cannot handle packet code %u",
				   packet->code);
		return -RSE_INVALID_REQUEST_CODE;
	}

#ifdef NR_NO_MALLOC
	if (!packet->data) {
		nr_debug_error("No place to put packet");
		return -RSE_NO_PACKET_DATA;
	}
#endif

	if (packet->sizeof_data < 20) {
		nr_debug_error("The buffer is too small to encode the packet");
		return -RSE_PACKET_TOO_SMALL;
	}

	/*
	 *	Enforce request / response correlation.
	 */
	if (original) {
		uint64_t mask;

		mask = 1;
		mask <<= packet->code;

		if ((allowed_responses[original->code] & mask) == 0) {
			nr_debug_error("Cannot encode response %u to packet %u",
					   packet->code, original->code);
			return -RSE_INVALID_RESPONSE_CODE;
		}
		packet->id = original->id;

	} else if (allowed_responses[packet->code] == 0) {
		nr_debug_error("Cannot encode response %u without original",
				   packet->code);
		return -RSE_REQUEST_REQUIRED;
	}

	return 0;
}

static void encode_header(RADIUS_PACKET *packet)
{
	if ((packet->flags & RS_PACKET_HEADER) != 0) return;

	memset(packet->data, 0, 20);
	packet->data[0] = packet->code;
	packet->data[1] = packet->id;
	packet->data[2] = 0;
	packet->data[3] = 20;
	packet->length = 20;

	/*
	 *	Calculate a random authentication vector.
	 */
	if ((packet->code == PW_ACCESS_REQUEST) ||
	    (packet->code == PW_STATUS_SERVER)) {
		nr_rand_bytes(packet->vector, sizeof(packet->vector));
	} else {
		memset(packet->vector, 0, sizeof(packet->vector));
	}

	memcpy(packet->data + 4, packet->vector, sizeof(packet->vector));

	packet->flags |= RS_PACKET_HEADER;
}

int nr_packet_encode(RADIUS_PACKET *packet, const RADIUS_PACKET *original)
{
#ifdef PW_MESSAGE_AUTHENTICATOR
	size_t ma = 0;
#endif
	int rcode;
	ssize_t len;
	const VALUE_PAIR *vp;
	uint8_t *data, *end;

	if ((packet->flags & RS_PACKET_ENCODED) != 0) return 0;

	rcode = can_encode_packet(packet, original);
	if (rcode < 0) return rcode;

	data = packet->data;
	end = data + packet->sizeof_data;

	encode_header(packet);
	data += 20;

	/*
	 *	Encode each VALUE_PAIR
	 */
	vp = packet->vps;
	while (vp) {
#ifdef PW_MESSAGE_AUTHENTICATOR
		if (vp->da->attr == PW_MESSAGE_AUTHENTICATOR) {
			ma = (data - packet->data);
		}
#endif
		len = nr_vp2attr(packet, original, &vp,
				  data, end - data);
		if (len < 0) return len;

		if (len == 0) break; /* insufficient room to encode it */

		data += data[1];
	}

#ifdef PW_MESSAGE_AUTHENTICATOR
	/*
	 *	Always send a Message-Authenticator.
	 *
	 *	We do *not* recommend removing this code.
	 */
	if (((packet->code == PW_ACCESS_REQUEST) ||
	     (packet->code == PW_STATUS_SERVER)) &&
	    !ma &&
	    ((data + 18) <= end)) {
		ma = (data - packet->data);
		data[0] = PW_MESSAGE_AUTHENTICATOR;
		data[1] = 18;
		memset(data + 2, 0, 16);
		data += data[1];
	}
#endif

	packet->length = data - packet->data;

	packet->data[2] = (packet->length >> 8) & 0xff;
	packet->data[3] = packet->length & 0xff;

	packet->flags |= RS_PACKET_ENCODED;

	return packet->length;
}


/*
 *	Ensure that the nr_data2attr_t structure is filled in
 *	appropriately.  This includes filling in a fake DICT_ATTR
 *	structure, if necessary.
 */
static int do_callback(void *ctx, nr_packet_walk_func_t callback,
		       int attr, int vendor,
		       const uint8_t *data, size_t sizeof_data)
		       
{
	int rcode;
	const DICT_ATTR *da;
	DICT_ATTR myda;
	char buffer[64];

	da = nr_dict_attr_byvalue(attr, vendor);

	/*
	 *	The attribute is supposed to have a particular length,
	 *	but does not.  It is therefore malformed.
	 */
	if (da && (da->flags.length != 0) &&
	    da->flags.length != sizeof_data) {
		da = NULL;
	}

	if (!da) {
		rcode = nr_dict_attr_2struct(&myda, attr, vendor,
					     buffer, sizeof(buffer));
		
		if (rcode < 0) return rcode;
		da = &myda;
	}
	
	rcode = callback(ctx, da, data, sizeof_data);
	if (rcode < 0) return rcode;

	return 0;
}


int nr_packet_walk(RADIUS_PACKET *packet, void *ctx,
		   nr_packet_walk_func_t callback)
{
	int rcode;
	uint8_t *attr;
	const uint8_t *end;

	if (!packet || !callback) return -RSE_INVAL;

	rcode = nr_packet_ok(packet);
	if (rcode < 0) return rcode;

	end = packet->data + packet->length;

	for (attr = packet->data + 20; attr < end; attr += attr[1]) {
		int length, value;
		int dv_type, dv_length;
		uint32_t vendorpec;
		const uint8_t *vsa;
		const DICT_VENDOR *dv = NULL;

		vendorpec = 0;
		value = attr[0];

		if (value != PW_VENDOR_SPECIFIC) {
		raw:
			rcode = do_callback(ctx, callback,
					    attr[0], 0,
					    attr + 2, attr[1] - 2);
			if (rcode < 0) return rcode;
			continue;
		}

		if (attr[1] < 6) goto raw;
		memcpy(&vendorpec, attr + 2, 4);
		vendorpec = ntohl(vendorpec);

		if (dv && (dv->vendor != vendorpec)) dv = NULL;

		if (!dv) dv = nr_dict_vendor_byvalue(vendorpec);

		if (dv) {
			dv_type = dv->type;
			dv_length = dv->length;
		} else {
			dv_type = 1;
			dv_length = 1;
		}

		/*
		 *	Malformed: it's a raw attribute.
		 */
		if (nr_tlv_ok(attr + 6, attr[1] - 6, dv_type, dv_length) < 0) {
			goto raw;
		}

		for (vsa = attr + 6; vsa < attr + attr[1]; vsa += length) {
			switch (dv_type) {
			case 4:
				value = (vsa[2] << 8) | vsa[3];
				break;

			case 2:
				value = (vsa[0] << 8) | vsa[1];
				break;

			case 1:
				value = vsa[0];
				break;

			default:
				return -RSE_INTERNAL;
			}

			switch (dv_length) {
			case 0:
				length = attr[1] - 6 - dv_type;
				break;

			case 2:
			case 1:
				length = vsa[dv_type + dv_length - 1];
				break;

			default:
				return -RSE_INTERNAL;
			}

			rcode = do_callback(ctx, callback,
					    value, vendorpec,
					    vsa + dv_type + dv_length,
					    length - dv_type - dv_length);
			if (rcode < 0) return rcode;
		}
	}

	return 0;
}

int nr_packet_init(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		   const char *secret, int code,
		   void *data, size_t sizeof_data)
{
	int rcode;

	if ((code < 0) || (code > RS_MAX_PACKET_CODE)) {
		return -RSE_INVALID_REQUEST_CODE;
	}

	if (!data || (sizeof_data < 20)) return -RSE_INVAL;

	memset(packet, 0, sizeof(*packet));
	packet->secret = secret;
	packet->sizeof_secret = secret ? strlen(secret) : 0;
	packet->code = code;
	packet->id = 0;
	packet->data = data;
	packet->sizeof_data = sizeof_data;

	rcode = can_encode_packet(packet, original);
	if (rcode < 0) return rcode;

	encode_header(packet);

	return 0;
}


static int pack_eap(RADIUS_PACKET *packet,
		    const void *data, size_t data_len)
{
	uint8_t *attr, *end;
	const uint8_t *eap;
	size_t left;
		
	eap = data;
	left = data_len;
	attr = packet->data + packet->length;
	end = attr + packet->sizeof_data;
	
	while (left > 253) {
		if ((attr + 255) > end) return -RSE_ATTR_OVERFLOW;
		
		attr[0] = PW_EAP_MESSAGE;
		attr[1] = 255;
		memcpy(attr + 2, eap, 253);
		attr += attr[1];
		eap += 253;
		left -= 253;
	}
	
	if ((attr + (2 + left)) > end) return -RSE_ATTR_OVERFLOW;
	
	attr[0] = PW_EAP_MESSAGE;
	attr[1] = 2 + left;
	memcpy(attr + 2, eap, left);
	attr += attr[1];
	packet->length = attr - packet->data;

	return 0;
}

ssize_t nr_packet_attr_append(RADIUS_PACKET *packet,
			      const RADIUS_PACKET *original,
			      const DICT_ATTR *da,
			      const void *data, size_t data_len)
{
	ssize_t rcode;
	uint8_t *attr, *end;
	VALUE_PAIR my_vp;
	const VALUE_PAIR *vp;

	if (!packet || !da || !data) {
		return -RSE_INVAL;
	}

	if (data_len == 0) {
		if (da->type != RS_TYPE_STRING) return -RSE_ATTR_TOO_SMALL;

		data_len = strlen(data);
	}

        /* We're going to mark the whole packet as encoded so we
           better not have any unencoded value-pairs attached. */
        if (packet->vps)
                return -RSE_INVAL;
	packet->flags |= RS_PACKET_ENCODED;

	attr = packet->data + packet->length;
	end = attr + packet->sizeof_data;

	if ((attr + 2 + data_len) > end) {
		return -RSE_ATTR_OVERFLOW;
	}

	if ((da->flags.length != 0) &&
	    (data_len != da->flags.length)) {
		return -RSE_ATTR_VALUE_MALFORMED;
	}

#ifdef PW_EAP_MESSAGE
	/*
	 *	automatically split EAP-Message into multiple
	 *	attributes.
	 */
	if (!da->vendor && (da->attr == PW_EAP_MESSAGE) && (data_len > 253)) {
		return pack_eap(packet, data, data_len);
	}
#endif

	if (data_len > 253) return -RSE_ATTR_TOO_LARGE;

	vp = nr_vp_init(&my_vp, da);
	rcode = nr_vp_set_data(&my_vp, data, data_len);
	if (rcode < 0) return rcode;

	/*
	 *	Note that this function packs VSAs each into their own
	 *	Vendor-Specific attribute.  If this isn't what you
	 *	want, use the version of the library with full support
	 *	for TLVs, WiMAX, and extended attributes.
	 */
	rcode = nr_vp2attr(packet, original, &vp, attr, end - attr);
	if (rcode <= 0) return rcode;

	packet->length += rcode;

	return rcode;
}
