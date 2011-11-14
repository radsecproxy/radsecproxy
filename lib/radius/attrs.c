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

/** \file attrs.c
 *  \brief Attribute encoding and decoding routines.
 */

#include "client.h"

/*
 *	Encodes the data portion of an attribute.
 *	Returns -1 on error, or the length of the data portion.
 */
static ssize_t vp2data_any(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   int nest,
			   const VALUE_PAIR **pvp,
			   uint8_t *start, size_t room)
{
	uint32_t lvalue;
	ssize_t len;
	const uint8_t *data;
	uint8_t *ptr = start;
	uint8_t	array[4];
	const VALUE_PAIR *vp = *pvp;

#ifdef RS_TYPE_TLV
	/*
	 *	See if we need to encode a TLV.  The low portion of
	 *	the attribute has already been placed into the packer.
	 *	If there are still attribute bytes left, then go
	 *	encode them as TLVs.
	 *
	 *	If we cared about the stack, we could unroll the loop.
	 */
	if ((nest > 0) && (nest <= nr_attr_max_tlv) &&
	    ((vp->da->attr >> nr_attr_shift[nest]) != 0)) {
		return vp2data_tlvs(packet, original, nest, pvp,
				    start, room);
	}
#else
	nest = nest;		/* -Wunused */
#endif

	/*
	 *	Set up the default sources for the data.
	 */
	data = vp->vp_octets;
	len = vp->length;

	switch(vp->da->type) {
	case RS_TYPE_IPV6PREFIX:
		len = sizeof(vp->vp_ipv6prefix);
		break;

	case RS_TYPE_STRING:
	case RS_TYPE_OCTETS:
	case RS_TYPE_IFID:
	case RS_TYPE_IPV6ADDR:
#ifdef RS_TYPE_ABINARY
	case RS_TYPE_ABINARY:
#endif
		/* nothing more to do */
		break;

	case RS_TYPE_BYTE:
		len = 1;	/* just in case */
		array[0] = vp->vp_integer & 0xff;
		data = array;
		break;

	case RS_TYPE_SHORT:
		len = 2;	/* just in case */
		array[0] = (vp->vp_integer >> 8) & 0xff;
		array[1] = vp->vp_integer & 0xff;
		data = array;
		break;

	case RS_TYPE_INTEGER:
		len = 4;	/* just in case */
		lvalue = htonl(vp->vp_integer);
		memcpy(array, &lvalue, sizeof(lvalue));
		data = array;
		break;

	case RS_TYPE_IPADDR:
		data = (const uint8_t *) &vp->vp_ipaddr;
		len = 4;	/* just in case */
		break;

		/*
		 *  There are no tagged date attributes.
		 */
	case RS_TYPE_DATE:
		lvalue = htonl(vp->vp_date);
		data = (const uint8_t *) &lvalue;
		len = 4;	/* just in case */
		break;

#ifdef VENDORPEC_WIMAX
	case RS_TYPE_SIGNED:
	{
		int32_t slvalue;

		len = 4;	/* just in case */
		slvalue = htonl(vp->vp_signed);
		memcpy(array, &slvalue, sizeof(slvalue));
		break;
	}
#endif

#ifdef RS_TYPE_TLV
	case RS_TYPE_TLV:
		data = vp->vp_tlv;
		if (!data) {
			nr_debug_error("ERROR: Cannot encode NULL TLV");
			return -RSE_INVAL;
		}
		len = vp->length;
		break;
#endif

	default:		/* unknown type: ignore it */
		nr_debug_error("ERROR: Unknown attribute type %d", vp->da->type);
		return -RSE_ATTR_TYPE_UNKNOWN;
	}

	/*
	 *	Bound the data to the calling size
	 */
	if (len > (ssize_t) room) len = room;

#ifndef FLAG_ENCRYPT_TUNNEL_PASSWORD
	original = original;	/* -Wunused */
#endif

	/*
	 *	Encrypt the various password styles
	 *
	 *	Attributes with encrypted values MUST be less than
	 *	128 bytes long.
	 */
	switch (vp->da->flags.encrypt) {
	case FLAG_ENCRYPT_USER_PASSWORD:
		len = nr_password_encrypt(ptr, room, data, len,
					  packet->secret, packet->vector);
		break;

#ifdef FLAG_ENCRYPT_TUNNEL_PASSWORD
	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		lvalue = 0;
		if (vp->da->flags.has_tag) lvalue = 1;

		/*
		 *	Check if there's enough room.  If there isn't,
		 *	we discard the attribute.
		 *
		 *	This is ONLY a problem if we have multiple VSA's
		 *	in one Vendor-Specific, though.
		 */
		if (room < (18 + lvalue)) {
			*pvp = vp->next;
			return 0;
		}

        	switch (packet->code) {
	        case PW_ACCESS_ACCEPT:
        	case PW_ACCESS_REJECT:
        	case PW_ACCESS_CHALLENGE:
        	default:
			if (!original) {
				nr_debug_error("ERROR: No request packet, cannot encrypt %s attribute in the vp.", vp->da->name);
				return -RSE_REQUEST_REQUIRED;
			}

			if (lvalue) ptr[0] = vp->tag;
			len = nr_tunnelpw_encrypt(ptr + lvalue,
						  room - lvalue, data, len,
						  packet->secret,
						  original->vector);
			if (len < 0) return len;
                	break;
	        case PW_ACCOUNTING_REQUEST:
        	case PW_DISCONNECT_REQUEST:
	        case PW_COA_REQUEST:
			ptr[0] = vp->tag;
			len = nr_tunnelpw_encrypt(ptr + 1, room, data, len - 1,
						  packet->secret,
						  packet->vector);
			if (len < 0) return len;
	                break;
        	}
		break;
#endif

		/*
		 *	The code above ensures that this attribute
		 *	always fits.
		 */
#ifdef FLAG_ENCRYPT_ASCEND_SECRET
	case FLAG_ENCRYPT_ASCEND_SECRET:
		make_secret(ptr, packet->vector, packet->secret, data);
		len = AUTH_VECTOR_LEN;
		break;
#endif

	default:
		if (vp->da->flags.has_tag && TAG_VALID(vp->tag)) {
			if (vp->da->type == RS_TYPE_STRING) {
				if (len > ((ssize_t) (room - 1))) len = room - 1;
				ptr[0] = vp->tag;
				ptr++;
			} else if (vp->da->type == RS_TYPE_INTEGER) {
				array[0] = vp->tag;
			} /* else it can't be any other type */
		}
		memcpy(ptr, data, len);
		break;
	} /* switch over encryption flags */

	*(pvp) = vp->next;
	return len + (ptr - start);;
}


/*
 *	Encode an RFC format TLV.  This could be a standard attribute,
 *	or a TLV data type.  If it's a standard attribute, then
 *	vp->da->attr == attribute.  Otherwise, attribute may be
 *	something else.
 */
static ssize_t vp2attr_rfc(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const VALUE_PAIR **pvp,
			   unsigned int attribute, uint8_t *ptr, size_t room)
{
	ssize_t len;

	if (room < 2) {
		*pvp = (*pvp)->next;
		return 0;
	}

	ptr[0] = attribute & 0xff;
	ptr[1] = 2;

	if (room > ((unsigned) 255 - ptr[1])) room = 255 - ptr[1];

	len = vp2data_any(packet, original, 0, pvp, ptr + ptr[1], room);
	if (len < 0) return len;

	ptr[1] += len;

	return ptr[1];
}


#ifndef WITHOUT_VSAS
/*
 *	Encode a VSA which is a TLV.  If it's in the RFC format, call
 *	vp2attr_rfc.  Otherwise, encode it here.
 */
static ssize_t vp2attr_vsa(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const VALUE_PAIR **pvp,
			   unsigned int attribute, unsigned int vendor,
			   uint8_t *ptr, size_t room)
{
	ssize_t len;
	const DICT_VENDOR *dv;

	/*
	 *	Unknown vendor: RFC format.
	 *	Known vendor and RFC format: go do that.
	 */
	dv = nr_dict_vendor_byvalue(vendor);
	if (!dv ||
	    (
#ifdef RS_TYPE_TLV
		    !(*pvp)->flags.is_tlv &&
#endif
		    (dv->type == 1) && (dv->length == 1))) {
		return vp2attr_rfc(packet, original, pvp,
				   attribute, ptr, room);
	}

#ifdef RS_TYPE_TLV
	if ((*pvp)->flags.is_tlv) {
		return data2vp_tlvs(packet, original, 0, pvp,
				    ptr, room);
	}
#endif

	switch (dv->type) {
	default:
		nr_debug_error("vp2attr_vsa: Internal sanity check failed,"
				   " type %u", (unsigned) dv->type);
		return -RSE_INTERNAL;

	case 4:
		ptr[0] = 0;	/* attr must be 24-bit */
		ptr[1] = (attribute >> 16) & 0xff;
		ptr[2] = (attribute >> 8) & 0xff;
		ptr[3] = attribute & 0xff;
		break;

	case 2:
		ptr[0] = (attribute >> 8) & 0xff;
		ptr[1] = attribute & 0xff;
		break;

	case 1:
		ptr[0] = attribute & 0xff;
		break;
	}

	switch (dv->length) {
	default:
		nr_debug_error("vp2attr_vsa: Internal sanity check failed,"
				   " length %u", (unsigned) dv->length);
		return -RSE_INTERNAL;

	case 0:
		break;

	case 2:
		ptr[dv->type] = 0;
		/* FALL-THROUGH */

	case 1:
		ptr[dv->type + dv->length - 1] = dv->type + dv->length;
		break;

	}

	if (room > ((unsigned) 255 - (dv->type + dv->length))) {
		room = 255 - (dv->type + dv->length);
	}

	len = vp2data_any(packet, original, 0, pvp,
			  ptr + dv->type + dv->length, room);
	if (len < 0) return len;

	if (dv->length) ptr[dv->type + dv->length - 1] += len;

	return dv->type + dv->length + len;
}


/*
 *	Encode a Vendor-Specific attribute.
 */
ssize_t nr_vp2vsa(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	      const VALUE_PAIR **pvp, uint8_t *ptr,
	      size_t room)
{
	ssize_t len;
	uint32_t lvalue;
	const VALUE_PAIR *vp = *pvp;

#ifdef VENDORPEC_WIMAX
	/*
	 *	Double-check for WiMAX
	 */
	if (vp->da->vendor == VENDORPEC_WIMAX) {
		return nr_vp2wimax(packet, original,  pvp,
				    ptr, room);
	}
#endif

	if (vp->da->vendor > RS_MAX_VENDOR) {
		nr_debug_error("nr_vp2vsa: Invalid arguments");
		return -RSE_INVAL;
	}

	/*
	 *	Not enough room for:
	 *		attr, len, vendor-id
	 */
	if (room < 6) {
		*pvp = vp->next;
		return 0;
	}

	/*
	 *	Build the Vendor-Specific header
	 */
	ptr[0] = PW_VENDOR_SPECIFIC;
	ptr[1] = 6;
	lvalue = htonl(vp->da->vendor);
	memcpy(ptr + 2, &lvalue, 4);

	if (room > ((unsigned) 255 - ptr[1])) room = 255 - ptr[1];

	len = vp2attr_vsa(packet, original, pvp,
			  vp->da->attr, vp->da->vendor,
			  ptr + ptr[1], room);
	if (len < 0) return len;

	ptr[1] += len;

	return ptr[1];
}
#endif


/*
 *	Encode an RFC standard attribute 1..255
 */
ssize_t nr_vp2rfc(const RADIUS_PACKET *packet,
	       const RADIUS_PACKET *original,
	       const VALUE_PAIR **pvp,
	       uint8_t *ptr, size_t room)
{
	const VALUE_PAIR *vp = *pvp;

	if (vp->da->vendor != 0) {
		nr_debug_error("nr_vp2rfc called with VSA");
		return -RSE_INVAL;
	}

	if ((vp->da->attr == 0) || (vp->da->attr > 255)) {
		nr_debug_error("nr_vp2rfc called with non-standard attribute %u", vp->da->attr);
		return -RSE_INVAL;
	}

#ifdef PW_CHARGEABLE_USER_IDENTITY
	if ((vp->length == 0) &&
	    (vp->da != RS_DA_CHARGEABLE_USER_IDENTITY)) {
		*pvp = vp->next;
		return 0;
	}
#endif

	return vp2attr_rfc(packet, original, pvp, vp->da->attr,
			   ptr, room);
}

#ifdef PW_CHAP_PASSWORD
/*
 *	Encode an RFC standard attribute 1..255
 */
static ssize_t nr_chap2rfc(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const VALUE_PAIR **pvp,
			uint8_t *ptr, size_t room)
{
	ssize_t rcode;
	const VALUE_PAIR *vp = *pvp;
	RS_MD5_CTX	ctx;
	uint8_t		buffer[RS_MAX_STRING_LEN*2 + 1], *p;
	VALUE_PAIR chap = {
		RS_DA_CHAP_PASSWORD,
		17,
		0,
		NULL,
		{
			.octets = {
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
			},
		},
	};

	if ((vp->da->vendor != 0) || (vp->da != RS_DA_CHAP_PASSWORD)) {
		nr_debug_error("nr_chap2rfc called with non-CHAP");
		return -RSE_INVAL;
	}

	p = buffer;
	*(p++) = nr_rand() & 0xff; /* id */

	memcpy(p, vp->vp_strvalue, strlen(vp->vp_strvalue));
	p += strlen(vp->vp_strvalue);

	vp = nr_vps_find(packet->vps, PW_CHAP_CHALLENGE, 0);
	if (vp) {
		memcpy(p, vp->vp_octets, vp->length);
		p += vp->length;
	} else {
		memcpy(p, packet->vector, sizeof(packet->vector));
		p += sizeof(packet->vector);
	}

	RS_MD5Init(&ctx);
	RS_MD5Update(&ctx, buffer, p - buffer);
	RS_MD5Final(&chap.vp_octets[1], &ctx);

	chap.vp_octets[0] = buffer[0];
	vp = &chap;

	rcode = vp2attr_rfc(packet, original, &vp, chap.da->attr,
			    ptr, room);
	if (rcode < 0) return rcode;

	*pvp = (*pvp)->next;
	return rcode;
}
#endif	/* PW_CHAP_PASSWORD */

#ifdef PW_MESSAGE_AUTHENTICATOR
/** Fake Message-Authenticator.
 *
 *  This structure is used to replace a Message-Authenticator in the
 *  input list of VALUE_PAIRs when encoding a packet.  If the caller
 *  asks us to encode a Message-Authenticator, we ignore the one given
 *  to us by the caller (which may have the wrong length, etc.), and
 *  instead use this one, which has the correct length and data.
 */
static const VALUE_PAIR fake_ma = {
	RS_DA_MESSAGE_AUTHENTICATOR,
	16,
	0,
	NULL,
	{
		.octets = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		},
	}
};
#endif	/* PW_MESSAGE_AUTHENTICATOR */

/*
 *	Parse a data structure into a RADIUS attribute.
 */
ssize_t nr_vp2attr(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		const VALUE_PAIR **pvp, uint8_t *start,
		size_t room)
{
	const VALUE_PAIR *vp = *pvp;

	/*
	 *	RFC format attributes take the fast path.
	 */
	if (vp->da->vendor != 0) {
#ifdef VENDORPEC_EXTENDED
		if (vp->da->vendor > RS_MAX_VENDOR) {
			return nr_vp2attr_extended(packet, original,
						   pvp, start, room);
						    
		}
#endif
		
#ifdef VENDORPEC_WIMAX
		if (vp->da->vendor == VENDORPEC_WIMAX) {
			return nr_vp2attr_wimax(packet, original,
						 pvp, start, room);
		}
#endif
		
#ifndef WITHOUT_VSAS
		return nr_vp2vsa(packet, original, pvp, start, room);
#else
		nr_debug_error("VSAs are not supported");
		return -RSE_UNSUPPORTED;
#endif
	}

	/*
	 *	Ignore non-protocol attributes.
	 */
	if (vp->da->attr > 255) {
		*pvp = vp->next;
		return 0;
	}

#ifdef PW_MESSAGE_AUTHENTICATOR
	/*
	 *	The caller wants a Message-Authenticator, but doesn't
	 *	know how to calculate it, or what the correct values
	 *	are.  So... create one for him.
	 */
	if (vp->da == RS_DA_MESSAGE_AUTHENTICATOR) {
		ssize_t rcode;

		vp = &fake_ma;
		rcode = nr_vp2rfc(packet, original, &vp, start, room);
		if (rcode <= 0) return rcode;
		*pvp = (*pvp)->next;
		return rcode;
	}
#endif

#ifdef PW_CHAP_PASSWORD
	/*
	 *	The caller wants a CHAP-Password, but doesn't know how
	 *	to calculate it, or what the correct values are.  To
	 *	help, we calculate it for him.
	 */
	if (vp->da == RS_DA_CHAP_PASSWORD) {
		int encoded = 0;

		/*
		 *	CHAP is ID + MD5(...).  If it's length is NOT
		 *	17, then the caller has passed us a password,
		 *	and wants us to encode it.  If the length IS
		 *	17, then we need to double-check if the caller
		 *	has already encoded it.
		 */
		if (vp->length == 17) {
			int i;

			/*
			 *	ASCII and UTF-8 disallow values 0..31.
			 *	If they appear, then the CHAP-Password
			 *	has already been encoded by the
			 *	caller.  The probability of a
			 *	CHAP-Password being all 32..256 is
			 *	(1-32/256)^17 =~ .10
			 *
			 *	This check isn't perfect, but it
			 *	should be pretty rare for people to
			 *	have 17-character passwords *and* have
			 *	them all 32..256.
			 */
			for (i = 0; i < 17; i++) {
				if (vp->vp_octets[i] < 32) {
					encoded = 1;
					break;
				}
			}
		}

		if (!encoded) {
			return nr_chap2rfc(packet, original, pvp, start, room);
		}
	}
#endif

	return nr_vp2rfc(packet, original, pvp,
			  start, room);
}


/*
 *	Ignore unknown attributes, but "decoding" them into nothing.
 */
static ssize_t data2vp_raw(UNUSED const RADIUS_PACKET *packet,
			   UNUSED const RADIUS_PACKET *original,
			   unsigned int attribute,
			   unsigned int vendor,
			   const uint8_t *data, size_t length,
			   VALUE_PAIR **pvp)
{
	VALUE_PAIR *vp;

	if (length > sizeof(vp->vp_octets)) return -RSE_ATTR_OVERFLOW;

	vp = nr_vp_alloc_raw(attribute, vendor);
	if (!vp) return -RSE_NOMEM;
	
	memcpy(vp->vp_octets, data, length);
	vp->length = length;

	*pvp = vp;
	return length;
}

ssize_t nr_attr2vp_raw(const RADIUS_PACKET *packet,
		       const RADIUS_PACKET *original,
		       const uint8_t *data, size_t length,
		       VALUE_PAIR **pvp)
{

	if (length < 2) return -RSE_PACKET_TOO_SMALL;
	if (data[1] < 2) return -RSE_ATTR_TOO_SMALL;
	if (data[1] > length) return -RSE_ATTR_OVERFLOW;

	return data2vp_raw(packet, original, data[0], 0,
			   data + 2, data[1] - 2, pvp);
}

/*
 *	Create any kind of VP from the attribute contents.
 *
 *	Will return -1 on error, or "length".
 */
static ssize_t data2vp_any(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   int nest,
			   unsigned int attribute, unsigned int vendor,
			   const uint8_t *data, size_t length,
			   VALUE_PAIR **pvp)
{
#ifdef FLAG_ENCRYPT_TUNNEL_PASSWORD
	ssize_t rcode;
#endif
	int data_offset = 0;
	const DICT_ATTR *da;
	VALUE_PAIR *vp = NULL;

	if (length == 0) {
		/*
		 *	Hacks for CUI.  The WiMAX spec says that it
		 *	can be zero length, even though this is
		 *	forbidden by the RADIUS specs.  So... we make
		 *	a special case for it.
		 */
		if ((vendor == 0) &&
		    (attribute == PW_CHARGEABLE_USER_IDENTITY)) {
			data = (const uint8_t *) "";
			length = 1;
		} else {
			*pvp = NULL;
			return 0;
		}
	}

	da = nr_dict_attr_byvalue(attribute, vendor);

	/*
	 *	Unknown attribute.  Create it as a "raw" attribute.
	 */
	if (!da) {
	raw:
		if (vp) nr_vp_free(&vp);
		return data2vp_raw(packet, original,
				   attribute, vendor, data, length, pvp);
	}

#ifdef RS_TYPE_TLV
	/*
	 *	TLVs are handled first.  They can't be tagged, and
	 *	they can't be encrypted.
	 */
	if (da->da->type == RS_TYPE_TLV) {
		return data2vp_tlvs(packet, original,
				    attribute, vendor, nest,
				    data, length, pvp);
	}
#else
	nest = nest;		/* -Wunused */
#endif

	/*
	 *	The attribute is known, and well formed.  We can now
	 *	create it.  The main failure from here on in is being
	 *	out of memory.
	 */
	vp = nr_vp_alloc(da);
	if (!vp) return -RSE_NOMEM;

	/*
	 *	Handle tags.
	 */
	if (vp->da->flags.has_tag) {
		if (TAG_VALID(data[0])
#ifdef FLAG_ENCRYPT_TUNNEL_PASSWORD
		    || (vp->da->flags.encrypt == FLAG_ENCRYPT_TUNNEL_PASSWORD)
#endif
			) {
			/*
			 *	Tunnel passwords REQUIRE a tag, even
			 *	if don't have a valid tag.
			 */
			vp->tag = data[0];

			if ((vp->da->type == RS_TYPE_STRING) ||
			    (vp->da->type == RS_TYPE_OCTETS)) {
				if (length == 0) goto raw;
				data_offset = 1;
			}
		}
	}

	/*
	 *	Copy the data to be decrypted
	 */
	vp->length = length - data_offset;
	memcpy(&vp->vp_octets[0], data + data_offset, vp->length);

	/*
	 *	Decrypt the attribute.
	 */
	switch (vp->da->flags.encrypt) {
		/*
		 *  User-Password
		 */
	case FLAG_ENCRYPT_USER_PASSWORD:
		if (original) {
			rcode = nr_password_encrypt(vp->vp_octets,
						    sizeof(vp->vp_strvalue),
						    data + data_offset, vp->length,
						    packet->secret,
						    original->vector);
		} else {
			rcode = nr_password_encrypt(vp->vp_octets,
						    sizeof(vp->vp_strvalue),
						    data + data_offset, vp->length,
						    packet->secret,
						    packet->vector);
		}
		if (rcode < 0) goto raw;
		vp->vp_strvalue[128] = '\0';
		vp->length = strlen(vp->vp_strvalue);
		break;

		/*
		 *	Tunnel-Password's may go ONLY
		 *	in response packets.
		 */
#ifdef FLAG_ENCRYPT_TUNNEL_PASSWORD
	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		if (!original) goto raw;

		rcode = nr_tunnelpw_decrypt(vp->vp_octets,
					    sizeof(vp->vp_octets),
					    data + data_offset, vp->length,
					    packet->secret, original->vector);
		if (rcode < 0) goto raw;
		vp->length = rcode;
		break;
#endif


#ifdef FLAG_ENCRYPT_ASCEND_SECRET
		/*
		 *  Ascend-Send-Secret
		 *  Ascend-Receive-Secret
		 */
	case FLAG_ENCRYPT_ASCEND_SECRET:
		if (!original) {
			goto raw;
		} else {
			uint8_t my_digest[AUTH_VECTOR_LEN];
			make_secret(my_digest,
				    original->vector,
				    packet->secret, data);
			memcpy(vp->vp_strvalue, my_digest,
			       AUTH_VECTOR_LEN );
			vp->vp_strvalue[AUTH_VECTOR_LEN] = '\0';
			vp->length = strlen(vp->vp_strvalue);
		}
		break;
#endif

	default:
		break;
	} /* switch over encryption flags */

	/*
	 *	Expected a certain length, but got something else.
	 */
	if ((vp->da->flags.length != 0) &&
	    (vp->length != vp->da->flags.length)) {
		goto raw;
	}

	switch (vp->da->type) {
	case RS_TYPE_STRING:
	case RS_TYPE_OCTETS:
#ifdef RS_TYPE_ABINARY
	case RS_TYPE_ABINARY:
#endif
		/* nothing more to do */
		break;

	case RS_TYPE_BYTE:
		vp->vp_integer = vp->vp_octets[0];
		break;


	case RS_TYPE_SHORT:
		vp->vp_integer = (vp->vp_octets[0] << 8) | vp->vp_octets[1];
		break;

	case RS_TYPE_INTEGER:
		memcpy(&vp->vp_integer, vp->vp_octets, 4);
		vp->vp_integer = ntohl(vp->vp_integer);

		if (vp->da->flags.has_tag) vp->vp_integer &= 0x00ffffff;
		break;

	case RS_TYPE_DATE:
		memcpy(&vp->vp_date, vp->vp_octets, 4);
		vp->vp_date = ntohl(vp->vp_date);
		break;


	case RS_TYPE_IPADDR:
		memcpy(&vp->vp_ipaddr, vp->vp_octets, 4);
		break;

		/*
		 *	IPv6 interface ID is 8 octets long.
		 */
	case RS_TYPE_IFID:
		/* vp->vp_ifid == vp->vp_octets */
		break;

		/*
		 *	IPv6 addresses are 16 octets long
		 */
	case RS_TYPE_IPV6ADDR:
		/* vp->vp_ipv6addr == vp->vp_octets */
		break;

		/*
		 *	IPv6 prefixes are 2 to 18 octets long.
		 *
		 *	RFC 3162: The first octet is unused.
		 *	The second is the length of the prefix
		 *	the rest are the prefix data.
		 *
		 *	The prefix length can have value 0 to 128.
		 */
	case RS_TYPE_IPV6PREFIX:
		if (vp->length < 2 || vp->length > 18) goto raw;
		if (vp->vp_octets[1] > 128) goto raw;

		/*
		 *	FIXME: double-check that
		 *	(vp->vp_octets[1] >> 3) matches vp->length + 2
		 */
		if (vp->length < 18) {
			memset(vp->vp_octets + vp->length, 0,
			       18 - vp->length);
		}
		break;

#ifdef VENDORPEC_WIMAX
	case RS_TYPE_SIGNED:
		if (vp->length != 4) goto raw;

		/*
		 *	Overload vp_integer for ntohl, which takes
		 *	uint32_t, not int32_t
		 */
		memcpy(&vp->vp_integer, vp->vp_octets, 4);
		vp->vp_integer = ntohl(vp->vp_integer);
		memcpy(&vp->vp_signed, &vp->vp_integer, 4);
		break;
#endif

#ifdef RS_TYPE_TLV
	case RS_TYPE_TLV:
		nr_vp_free(&vp);
		nr_debug_error("data2vp_any: Internal sanity check failed");
		return -RSE_ATTR_TYPE_UNKNOWN;
#endif

#ifdef VENDORPEC_WIMAX
	case RS_TYPE_COMBO_IP:
		if (vp->length == 4) {
			vp->da->type = RS_TYPE_IPADDR;
			memcpy(&vp->vp_ipaddr, vp->vp_octets, 4);
			break;

		} else if (vp->length == 16) {
			vp->da->type = RS_TYPE_IPV6ADDR;
			/* vp->vp_ipv6addr == vp->vp_octets */
			break;

		}
		/* FALL-THROUGH */
#endif

	default:
		goto raw;
	}

	*pvp = vp;

	return length;
}


/*
 *	Create a "standard" RFC VALUE_PAIR from the given data.
 */
ssize_t nr_attr2vp_rfc(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp)
{
	ssize_t rcode;

	if (length < 2) return -RSE_PACKET_TOO_SMALL;
	if (data[1] < 2) return -RSE_ATTR_TOO_SMALL;
	if (data[1] > length) return -RSE_ATTR_OVERFLOW;
	
	rcode = data2vp_any(packet, original, 0,
			    data[0], 0, data + 2, data[1] - 2, pvp);
	if (rcode < 0) return rcode;

	return data[1];
}	

#ifndef WITHOUT_VSAS
/*
 *	Check if a set of RADIUS formatted TLVs are OK.
 */
int nr_tlv_ok(const uint8_t *data, size_t length,
	       size_t dv_type, size_t dv_length)
{
	const uint8_t *end = data + length;

	if ((dv_length > 2) || (dv_type == 0) || (dv_type > 4)) {
		nr_debug_error("nr_tlv_ok: Invalid arguments");
		return -RSE_INVAL;
	}

	while (data < end) {
		size_t attrlen;

		if ((data + dv_type + dv_length) > end) {
			nr_debug_error("Attribute header overflow");
			return -RSE_ATTR_TOO_SMALL;
		}

		switch (dv_type) {
		case 4:
			if ((data[0] == 0) && (data[1] == 0) &&
			    (data[2] == 0) && (data[3] == 0)) {
			zero:
				nr_debug_error("Invalid attribute 0");
				return -RSE_ATTR_INVALID;
			}

			if (data[0] != 0) {
				nr_debug_error("Invalid attribute > 2^24");
				return -RSE_ATTR_INVALID;
			}
			break;

		case 2:
			if ((data[1] == 0) && (data[1] == 0)) goto zero;
			break;

		case 1:
			if (data[0] == 0) goto zero;
			break;

		default:
			nr_debug_error("Internal sanity check failed");
			return -RSE_INTERNAL;
		}

		switch (dv_length) {
		case 0:
			return 0;

		case 2:
			if (data[dv_type + 1] != 0) {
				nr_debug_error("Attribute is longer than 256 octets");
				return -RSE_ATTR_TOO_LARGE;
			}
			/* FALL-THROUGH */
		case 1:
			attrlen = data[dv_type + dv_length - 1];
			break;


		default:
			nr_debug_error("Internal sanity check failed");
			return -RSE_INTERNAL;
		}

		if (attrlen < (dv_type + dv_length)) {
			nr_debug_error("Attribute header has invalid length");
			return -RSE_PACKET_TOO_SMALL;
		}

		if (attrlen > length) {
			nr_debug_error("Attribute overflows container");
			return -RSE_ATTR_OVERFLOW;
		}

		data += attrlen;
		length -= attrlen;
	}

	return 0;
}


/*
 *	Convert a top-level VSA to a VP.
 */
static ssize_t attr2vp_vsa(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   unsigned int vendor,
			   size_t dv_type, size_t dv_length,
			   const uint8_t *data, size_t length,
			   VALUE_PAIR **pvp)
{
	unsigned int attribute;
	ssize_t attrlen, my_len;

#ifndef NDEBUG
	if (length <= (dv_type + dv_length)) {
		nr_debug_error("attr2vp_vsa: Failure to call nr_tlv_ok");
		return -RSE_PACKET_TOO_SMALL;
	}
#endif	

	switch (dv_type) {
	case 4:
		/* data[0] must be zero */
		attribute = data[1] << 16;
		attribute |= data[2] << 8;
		attribute |= data[3];
		break;

	case 2:
		attribute = data[0] << 8;
		attribute |= data[1];
		break;

	case 1:
		attribute = data[0];
		break;

	default:
		nr_debug_error("attr2vp_vsa: Internal sanity check failed");
		return -RSE_INTERNAL;
	}

	switch (dv_length) {
	case 2:
		/* data[dv_type] must be zero */
		attrlen = data[dv_type + 1];
		break;

	case 1:
		attrlen = data[dv_type];
		break;

	case 0:
		attrlen = length;
		break;

	default:
		nr_debug_error("attr2vp_vsa: Internal sanity check failed");
		return -RSE_INTERNAL;
	}

#ifndef NDEBUG
	if (attrlen <= (ssize_t) (dv_type + dv_length)) {
		nr_debug_error("attr2vp_vsa: Failure to call nr_tlv_ok");
		return -RSE_PACKET_TOO_SMALL;
	}
#endif

	attrlen -= (dv_type + dv_length);
	
	my_len = data2vp_any(packet, original, 0,
			     attribute, vendor,
			     data + dv_type + dv_length, attrlen, pvp);
	if (my_len < 0) return my_len;

#ifndef NDEBUG
	if (my_len != attrlen) {
		nr_vp_free(pvp);
		nr_debug_error("attr2vp_vsa: Incomplete decode %d != %d",
				   (int) my_len, (int) attrlen);
		return -RSE_INTERNAL;
	}
#endif

	return dv_type + dv_length + attrlen;
}


/*
 *	Create Vendor-Specifc VALUE_PAIRs from a RADIUS attribute.
 */
ssize_t nr_attr2vp_vsa(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp)
{
	size_t dv_type, dv_length;
	ssize_t my_len;
	uint32_t lvalue;
	const DICT_VENDOR *dv;

	if (length < 2) return -RSE_PACKET_TOO_SMALL;
	if (data[1] < 2) return -RSE_ATTR_TOO_SMALL;
	if (data[1] > length) return -RSE_ATTR_OVERFLOW;

	if (data[0] != PW_VENDOR_SPECIFIC) {
		nr_debug_error("nr_attr2vp_vsa: Invalid attribute");
		return -RSE_INVAL;
	}

	/*
	 *	Not enough room for a Vendor-Id.
	 *	Or the high octet of the Vendor-Id is set.
	 */
	if ((data[1] < 6) || (data[2] != 0)) {
		return nr_attr2vp_raw(packet, original,
				       data, length, pvp);
	}

	memcpy(&lvalue, data + 2, 4);
	lvalue = ntohl(lvalue);

#ifdef VENDORPEC_WIMAX
	/*
	 *	WiMAX gets its own set of magic.
	 */
	if (lvalue == VENDORPEC_WIMAX) {
		return nr_attr2vp_wimax(packet, original,
					 data, length, pvp);
	}
#endif

	dv_type = dv_length = 1;
	dv = nr_dict_vendor_byvalue(lvalue);
	if (!dv) {
		return nr_attr2vp_rfc(packet, original,
				       data, length, pvp);
	}

	dv_type = dv->type;
	dv_length = dv->length;

	/*
	 *	Attribute is not in the correct form.
	 */
	if (nr_tlv_ok(data + 6, data[1] - 6, dv_type, dv_length) < 0) {
		return nr_attr2vp_raw(packet, original,
				       data, length, pvp);
	}

	my_len = attr2vp_vsa(packet, original,
			     lvalue, dv_type, dv_length,
			     data + 6, data[1] - 6, pvp);
	if (my_len < 0) return my_len;

#ifndef NDEBUG
	if (my_len != (data[1] - 6)) {
		nr_vp_free(pvp);
		nr_debug_error("nr_attr2vp_vsa: Incomplete decode");
		return -RSE_INTERNAL;
	}
#endif

	return data[1];
}
#endif	/* WITHOUT_VSAS */


/*
 *	Create a "normal" VALUE_PAIR from the given data.
 */
ssize_t nr_attr2vp(const RADIUS_PACKET *packet,
		    const RADIUS_PACKET *original,
		    const uint8_t *data, size_t length,
		    VALUE_PAIR **pvp)
{
	if (length < 2) return -RSE_PACKET_TOO_SMALL;
	if (data[1] < 2) return -RSE_ATTR_TOO_SMALL;
	if (data[1] > length) return -RSE_ATTR_OVERFLOW;

#ifndef WITHOUT_VSAS
	/*
	 *	VSAs get their own handler.
	 */
	if (data[0] == PW_VENDOR_SPECIFIC) {
		return nr_attr2vp_vsa(packet, original,
				       data, length, pvp);
	}
#endif

#ifdef VENDORPEC_EXTENDED
	/*
	 *	Extended attribute format gets their own handler.
	 */
	if (nr_dict_attr_byvalue(data[0], VENDORPEC_EXTENDED) != NULL) {
		return nr_attr2vp_extended(packet, original,
					    data, length, pvp);
	}
#endif

	return nr_attr2vp_rfc(packet, original, data, length, pvp);
}

ssize_t nr_attr2data(const RADIUS_PACKET *packet, ssize_t start,
		      unsigned int attribute, unsigned int vendor,
		      const uint8_t **pdata, size_t *plength)
{
	uint8_t *data, *attr;
	const uint8_t *end;

	if (!packet || !pdata || !plength) return -RSE_INVAL;

	if (!packet->data) return -RSE_INVAL;
	if (packet->length < 20) return -RSE_INVAL;

	/*
	 *	Too long or short, not good.
	 */
	if ((start < 0) ||
	    ((start > 0) && (start < 20))) return -RSE_INVAL;

	if ((size_t) start >= (packet->length - 2)) return -RSE_INVAL;

	end = packet->data + packet->length;

	/*
	 *	Loop over the packet, converting attrs to VPs.
	 */
	if (start == 0) {
		data = packet->data + 20;
	} else {
		data = packet->data + start;
		data += data[1];
		if (data >= end) return 0;
	}

	for (attr = data; attr < end; attr += attr[1]) {
		const DICT_VENDOR *dv = NULL;

#ifndef NEBUG
		/*
		 *	This code is copied from packet_ok().
		 *	It could be put into a separate function.
		 */
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
#endif

		if ((vendor == 0) && (attr[0] == attribute)) {
			*pdata = attr + 2;
			*plength = attr[1] - 2;
			return attr - packet->data;
		}

#ifndef WITHOUT_VSAS
		if (vendor != 0) {
			uint32_t vendorpec;

			if (attr[0] != PW_VENDOR_SPECIFIC) continue;

			if (attr[1] < 6) continue;

			memcpy(&vendorpec, attr + 2, 4);
			vendorpec = ntohl(vendorpec);
			if (vendor != vendorpec) continue;

			if (!dv) {
				dv = nr_dict_vendor_byvalue(vendor);
				if (dv &&
				    ((dv->type != 1) || (dv->length != 1))) {
					return -RSE_VENDOR_UNKNOWN;
				}
			}

			/*
			 *	No data.
			 */
			if (attr[1] < 9) continue;

			/*
			 *	Malformed, or more than one VSA in
			 *	the Vendor-Specific
			 */
			if (attr[7] + 6 != attr[1]) continue;

			/*
			 *	Not the right VSA.
			 */
			if (attr[6] != attribute) continue;

			*pdata = attr + 8;
			*plength = attr[1] - 8;
			return attr - packet->data;
		}
#endif
	}

	return 0;		/* nothing more: stop */
}

