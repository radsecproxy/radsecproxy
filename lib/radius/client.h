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

/** \file client.h
 *  \brief Main header file.
 */

#ifndef _RADIUS_CLIENT_H_
#define _RADIUS_CLIENT_H_ 1

/*
 *  System-specific header files.
 */
#include <config.h>
#include <errno.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdarg.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include <radsec/radius.h>

/** \defgroup build Build Helpers
 *
 * These definitions give the GNU C compiler more information about
 * the functions being compiled.  They are used to either remove
 * warnings, or to enable better warnings.
 **/

/** \defgroup custom Portability Functions
 *
 * These functions and definitions should be modified for your local
 * system.  See the individual definitions for details.
 */

/** \defgroup error Error handling
 *
 * These definitions and routines manage errors.
 */

/** \defgroup value_pair Attribute manipulation
 *
 * These routines manage structures which map to attributes.
 */

/**\defgroup dict Dictionary Lookup Functions
 *
 * \sa doc/dictionaries.txt
 *
 * The RADIUS dictionaries perform name to number mappings.  The names
 * are used only for administrator convenience, for parsing
 * configuration files, and printing humanly-readable output.  The
 * numbers are used when encoding data in a packet.
 *
 * When attributes are decoded from a packet, the numbers are used to
 * look up the associated name, which is then placed into a data
 * structure.
 *
 * When the data structures are encoded into a packet, the numbers are
 * used to create RFC and VSA format attributes.
 *
 * \attention The definitions, structures, and functions given below
 * are useful only for implementing "low level" RADIUS
 * functionality. There is usually no need to refer to them in a
 * client application.  The library should be used at a higher level,
 * which exposes a much simpler API.
 */

/** \defgroup packet Packet manipulation
 *
 * These routines perform encoding and decoding of RADIUS packets.
 */

/** \defgroup print Print / parse functions
 *
 * These routines convert the internal data structures to a printable
 * form, or parse them.
 */

/** \defgroup id ID allocation and freeing
 *
 *  These routines manage RADIUS ID allocation.
 */

/** \defgroup attr Low-level attribute encode/decoding
 *
 * These routines perform "low level" encoding, decoding, sending, and
 * reception of RADIUS attributes.  They are called by the \ref packet
 * functions.
 *
 * \attention The structures and functions given below are useful only
 * for implementing "low level" RADIUS functionality. There is usually
 * no need to refer to them in a client application.  The library
 * should be used at a higher level, which exposes a much simpler API.
 */

/** \defgroup internal Internal support functions.
 *
 * These functions are required to perform internal or "low-level"
 * data manipulation.  While they are exposed for completeness, they
 * should not be called by any application.
 */

#ifdef PW_EAP_MESSAGE
#ifndef PW_MESSAGE_AUTHENTICATOR
#error EAP-Message requires Message-Authenticator
#endif
#endif

#ifdef WITHOUT_OPENSSL
#ifndef RS_MD5_CTX
#error RS_MD5_CTX must be defined
#endif
#ifndef RS_MD5Init
#error n_rMD5Init must be defined
#endif
#ifndef RS_MD5Update
#error RS_MD5Updyae must be defined
#endif
#ifndef RS_MD5Final
#error RS_MD5Final must be defined
#endif
#ifndef RS_MD5Transform
#error RS_MD5Transform must be defined
#endif

#else  /* WITHOUT_OPENSSL */

#include <openssl/md5.h>
/** Define for compile-time selection of the MD5 functions.  Defaults to using the OpenSSL functions.  \ingroup custom */
#define RS_MD5_CTX	MD5_CTX
/** Define for compile-time selection of the MD5 functions.  Defaults to using the OpenSSL functions. \ingroup custom */
#define RS_MD5Init	MD5_Init
/** Define for compile-time selection of the MD5 functions.  Defaults to using the OpenSSL functions. \ingroup custom */
#define RS_MD5Update	MD5_Update
/** Define for compile-time selection of the MD5 functions.  Defaults to using the OpenSSL functions. \ingroup custom */
#define RS_MD5Final	MD5_Final
/** Define for compile-time selection of the MD5 functions.  Defaults to using the OpenSSL functions. \ingroup custom */
#define RS_MD5Transform MD5_Transform
#endif

#ifndef RS_MAX_PACKET_LEN
/** The maximum size of a packet that the library will send or receive.  \ingroup custom
 *
 *  The RFC requirement is to handle at least 4K packets.  However, if
 *  you expect to only do username/password authentication, this value
 *  can be set to a smaller value, such as 256.
 *
 *  Be warned that any packets larger than this value will be ignored
 *  and silently discarded.
 */
#define RS_MAX_PACKET_LEN (4096)
#endif

#ifndef RS_MAX_ATTRIBUTES
/** The maximum number of attributes that the library will allow in a packet.  \ingroup custom
 *
 *  Packets which contain more than ::RS_MAX_ATTRIBUTES will generate
 *  an error.  This value is configurable because there may be a need
 *  to accept a large mumber of attributes.
 *
 *  This value is ignored when packets are sent.  The library will
 *  send as many attributes as it is told to send.
 */
#define RS_MAX_ATTRIBUTES (200)
#endif

#undef RS_MAX_PACKET_CODE
/** The maximum RADIUS_PACKET::code which we can accept. \ingroup dict
 *
 *  \attention This should not be changed, as it is used by other
 *  structures such as ::nr_packet_codes.
 */
#define RS_MAX_PACKET_CODE PW_COA_NAK

/**  The maximum vendor number which is permitted. \ingroup dict
 *
 *  The RFCs require that the Vendor Id or Private Enterprise Number
 *  be encoded as 32 bits, with the upper 8 bits being zero.
 */
#define RS_MAX_VENDOR		(1 << 24)

/** Data Type Definitions. \ingroup dict
 */
#define TAG_VALID(x)          ((x) < 0x20)

/** The attribute is not encrypted. */
#define FLAG_ENCRYPT_NONE            (0)

/** The attribute is encrypted using the RFC 2865 User-Password method */
#define FLAG_ENCRYPT_USER_PASSWORD   (1)

/** The attribute is encrypted using the RFC 2868 Tunnel-Password method */
#define FLAG_ENCRYPT_TUNNEL_PASSWORD (2)

/** A set of flags which determine how the attribute should be handled.
 *
 * Most attributes are "normal", and do not require special handling.
 * However, some require "encryption", tagging, or have other special
 * formats.  This structure contains the various options for the
 * attribute formats.
 */
typedef struct attr_flags {
	unsigned int		has_tag : 1; /**< Attribute has an RFC 2868 tag */
	unsigned int		unknown : 1; /**< Attribute is unknown */
#ifdef RS_TYPE_TLV
	unsigned int		has_tlv : 1; /* has sub attributes */
	unsigned int		is_tlv : 1; /* is a sub attribute */
#endif
	unsigned int		extended : 1; /* extended attribute */
	unsigned int		extended_flags : 1; /* with flag */
	unsigned int		evs : 1;	    /* extended VSA */
	uint8_t		        encrypt;      /**< Attribute encryption method */
	uint8_t			length;	      /**< The expected length of the attribute */
} ATTR_FLAGS;


/** Defines an dictionary mapping for an attribute.  \ingroup dict
 *
 *  The RADIUS dictionaries map humanly readable names to protocol
 *  numbers.  The protocol numbers are used to encode/decode the
 *  attributes in a packet.
 */
typedef struct nr_dict_attr {
	unsigned int		attr;		/**< Attribute number  */
	rs_attr_type_t	      	type;		/**< Data type */
	unsigned int		vendor;		/**< Vendor-Id number  */
        ATTR_FLAGS              flags;
	const char		*name;		/**< Printable name  */
} DICT_ATTR;

/** Defines a dictionary mapping for a named enumeration.  \ingroup dict
 *
 *  This structure is currently not used.
 */
typedef struct nr_dict_value {
	const DICT_ATTR		*da;		/**< pointer to a ::DICT_ATTR  */
	int			value;		/**< enumerated value  */
	char			name[1];	/**< printable name  */
} DICT_VALUE;

/** Defines an dictionary mapping for a vendor.  \ingroup dict
 *
 *  The RADIUS dictionaries map humanly readable vendor names to a
 *  Vendor-Id (or Private Enterprise Code) assigned by IANA.  The
 *  Vendor-Id is used to encode/decode Vendor-Specific attributes in a
 *  packet.
 */
typedef struct nr_dict_vendor {
	unsigned int		vendor; /**< Vendor Private Enterprise Code  */
	size_t			type;	   /**< size of Vendor-Type field */
	size_t			length;    /**< size of Vendor-Length field */
	const char		*name;		/**< Printable name  */
} DICT_VENDOR;

/** Union holding all possible types of data for a ::VALUE_PAIR. \ingroup value_pair
 *
 */
typedef union value_pair_data {
	char			strvalue[RS_MAX_STRING_LEN]; /* +1 for NUL */
	uint8_t			octets[253];
	struct in_addr		ipaddr;
	struct in6_addr		ipv6addr;
	uint32_t		date;
	uint32_t		integer;
#ifdef RS_TYPE_SIGNED
	int32_t			sinteger;
#endif
#ifdef RS_TYPE_ABINARY
	uint8_t			filter[32];
#endif
	uint8_t			ifid[8]; /* struct? */
	uint8_t			ipv6prefix[18]; /* struct? */
#ifdef RS_TYPE_TLV
	uint8_t			*tlv;
#endif
} VALUE_PAIR_DATA;


/** C structure version of a RADIUS attribute. \ingroup value_pair
 *
 * The library APIs use this structure to avoid depending on the
 * details of the protocol.
 */
typedef struct value_pair {
	const DICT_ATTR		*da; /**< dictionary definition */
	size_t			length;	/**< number of octets in the data */
	int			tag; /**< tag value if da->flags.has_tag */
	struct value_pair	*next; /**< enables a linked list of values  */
	VALUE_PAIR_DATA		data;  /**< the data of the attribute */
} VALUE_PAIR;
#define vp_strvalue   data.strvalue
#define vp_octets     data.octets
#define vp_ipv6addr   data.ipv6addr
#define vp_ifid       data.ifid
#define vp_ipv6prefix data.ipv6prefix
#define vp_ipaddr     data.ipaddr.s_addr
#define vp_date       data.integer
#define vp_integer    data.integer
#ifdef RS_TYPE_ABINARY
#define vp_filter     data.filter
#endif
#ifdef RS_TYPE_ETHER
#define vp_ether      data.ether
#endif
#ifdef RS_TYPE_SIGNED
#define vp_signed     data.sinteger
#endif
#ifdef RS_TYPE_TLV
#define vp_tlv	      data.tlv
#endif

#ifdef RS_TYPE_TLV
#define RS_ATTR_MAX_TLV (4)
extern const int nr_attr_shift[RS_ATTR_MAX_TLV];
extern const int nr_attr_mask[RS_ATTR_MAX_TLV];
extern const unsigned int nr_attr_max_tlv;
#endif

/** A structure which describes a RADIUS packet. \ingroup packet
 *
 *  In general, it should not be necessary to refererence the elements
 *  of this structure.
 */
typedef struct radius_packet {
	int			sockfd; /** The socket descriptor */
	struct sockaddr_storage	src;    /**< The packet source address  */
        struct sockaddr_storage	dst;    /**< the packet destination address */
	const char		*secret; /**< The shared secret */
	size_t			sizeof_secret; /**< Length of the shared secret */
	unsigned int		code;	/**< The RADIUS Packet Code */
	int			id;	/**< The RADIUS Packet Id */
	size_t			length; /**< The RADIUS Packet Length.  This will be no larger than RADIUS_PACKET::sizeof_data */
	uint8_t			vector[16]; /**< A copy of the authentication vector */
	int			flags; /**< Internal flags.  Do not modify this field. */
	int			attempts; /**< The number of transmission attempt  */
	uint8_t			*data;	  /**< The raw packet data  */
	size_t			sizeof_data; /**< size of the data buffer  */
	VALUE_PAIR		*vps;	/**< linked list of ::VALUE_PAIR */
} RADIUS_PACKET;

#define RS_PACKET_ENCODED  (1 << 0)
#define RS_PACKET_HEADER   (1 << 1)
#define RS_PACKET_SIGNED   (1 << 2)
#define RS_PACKET_OK	   (1 << 3)
#define RS_PACKET_VERIFIED (1 << 4)
#define RS_PACKET_DECODED  (1 << 5)


/** Track packets sent to a server. \ingroup id
 *
 * This data structure tracks Identifiers which are used to
 * communicate with a particular destination server.  The application
 * should call nr_server_init() to initialize it.  If necessary, the
 * application should then call nr_server_set_ipv4() to open an IPv4
 * socket to the server.
 *
 * If the RADIUS packets are being transported over an encapsulation
 * layer (e.g. RADIUS over TLS), then nr_server_set_ipv4() does not
 * need to be called.  The ::nr_server_t structure should instead be
 * associated wih the TLS session / socket.
 */
typedef struct nr_server_t {
	int sockfd;		/**< socket for sending packets  */
	int code;		/**< default value for the Code */

	struct sockaddr_storage src; /**< Source address of the packet */
	struct sockaddr_storage dst; /**< Destination address of the packet  */

	/** The shared secret.
	 *
	 *  See also nr_packet_send() and nr_packet_recv().
	 */
	const char	*secret;

	/** The length of the shared secret.
	 *
	 *  See also nr_packet_send() and nr_packet_recv().
	 */
	size_t		sizeof_secret;

	int		used;	/**< Number of used IDs */

	void		*free_list; /**< For managing packets */

	RADIUS_PACKET	*ids[256]; /**< Pointers to "in flight" packets  */
} nr_server_t;


/** Return a printable error message. \ingroup error
 *
 *  This function returns a string describing the last error that
 *  occurred.  These messages are intended for developers, and are not
 *  suitable for display to an end user.  The application using this
 *  library should instead produce a "summary" message when an error
 *  occurs.  e.g. "Failed to receive a response", is better than
 *  messages produced by this function, which contain text like
 *  "invalid response authentication vector".  The first is
 *  understandable, the second is not.
 *
 * @param[in] error   The error code (can be less than zero)
 * @return            A printable string describing the error.
 */
extern const char *nr_strerror(int error);

/** Allocate a ::VALUE_PAIR which refers to a ::DICT_ATTR.  \ingroup value_pair
 *
 *  This returned ::VALUE_PAIR has no data associated with it.  The
 *  nr_vp_set_data() function must be called before placing the
 *  ::VALUE_PAIR in a ::RADIUS_PACKET.
 *
 * @param[in] da       The ::DICT_ATTR associated with the ::VALUE_PAIR
 * @return             The created ::VALUE_PAIR, or NULL on error.
 */
extern VALUE_PAIR *nr_vp_alloc(const DICT_ATTR *da);

/** Free a ::VALUE_PAIR.  \ingroup value_pair
 *
 *  This function frees the ::VALUE_PAIR, and sets the head pointer to NULL.
 *  If head refers to a ::VALUE_PAIR list, then all of the structures in the
 *  list are freed.
 *
 * @param[in,out] head   The pointer to a ::VALUE_PAIR, or a ::VALUE_PAIR list.
 */
extern void nr_vp_free(VALUE_PAIR **head);

/** Initializes a ::VALUE_PAIR from a ::DICT_ATTR \ingroup value_pair
 *
 *  This function assumes that the ::VALUE_PAIR points to existing
 *  and writable memory.
 *
 * @param[in,out] vp   The ::VALUE_PAIR to be initialized
 * @param[in] da       The ::DICT_ATTR used to initialize the ::VALUE_PAIR
 * @return             The initialized  ::VALUE_PAIR, or NULL on error.
 */
extern VALUE_PAIR *nr_vp_init(VALUE_PAIR *vp, const DICT_ATTR *da);

/** Allocate a ::VALUE_PAIR which refers to an unknown attribute.  \ingroup value_pair
 *
 *  It is used when an attribute is received, and that attribute does
 *  not exist in the dictionaries.
 *
 *  The returned ::VALUE_PAIR has no data (i.e. VALUE_PAIR::length is
 *  zero).  The nr_vp_set_data() function must be called before
 *  placing the ::VALUE_PAIR in a ::RADIUS_PACKET.
 *
 * @param[in] attr     The attribute number, 0..2^16
 * @param[in] vendor   The vendor number, 0..2^16
 * @return             The created ::VALUE_PAIR, or NULL on error.
 */
extern VALUE_PAIR *nr_vp_alloc_raw(unsigned int attr, unsigned int vendor);

/** Set the data associated with a previously allocated ::VALUE_PAIR.  \ingroup value_pair
 *
 *  If this function succeeds, VALUE_PAIR::length is no longer zero,
 *  and the structure contains the data.
 *
 * @param[in,out] vp   The ::VALUE_PAIR to update
 * @param[in] data     Data to set inside of the ::VALUE_PAIR
 * @param[in] data_len Length of the data field
 * @return             <0 on error, 0 for "data was truncated"
 *                      >0 for "data successfully added"
 */
extern int nr_vp_set_data(VALUE_PAIR *vp, const void *data, size_t data_len);

/** Create a ::VALUE_PAIR and set its data.  \ingroup value_pair
 *
 * @param[in] attr     The attribute number of the ::VALUE_PAIR to create
 * @param[in] vendor   The vendor number of the ::VALUE_PAIR to create
 * @param[in] data     Data to set inside of the ::VALUE_PAIR
 * @param[in] data_len Length of the data field
 * @return             The created ::VALUE_PAIR, or NULL on error.
 */
extern VALUE_PAIR *nr_vp_create(int attr, int vendor, const void *data,
			      size_t data_len);

/** Append a ::VALUE_PAIR to the end of a ::VALUE_PAIR list.  \ingroup value_pair
 *
 * @param[in,out] head The head of the ::VALUE_PAIR list.  May not be NULL.
 * @param[in] vp       The ::VALUE_PAIR to append to the list.
 */
extern void nr_vps_append(VALUE_PAIR **head, VALUE_PAIR *vp);

/** Search a ::VALUE_PAIR list for one of a given number.  \ingroup value_pair
 *
 * @param[in] head     The head of the ::VALUE_PAIR list to search.
 * @param[in] attr     The attribute number of the ::VALUE_PAIR to find
 * @param[in] vendor   The vendor number of the ::VALUE_PAIR to find
 * @return             The found ::VALUE_PAIR, or NULL if it was not found.
 */
extern VALUE_PAIR *nr_vps_find(VALUE_PAIR *head,
			    unsigned int attr, unsigned int vendor);

/** Look up an attribute in the dictionaries.  \ingroup dict
 *
 *  The dictionary mapping contains information about the attribute,
 *  such as printable name, data type (ipaddr, integer, etc), and
 *  various other things used to encode/decode the attribute in a
 *  packet.
 *
 *  \attention There is usually no need to call this function.  Use
 *  the RS_DA_* definitions instead.
 *
 * @param[in] attr    Value of the attribute
 * @param[in] vendor  Value of the vendor
 * @return    NULL for "not found", or a pointer to the attribute mapping.
 */
extern const DICT_ATTR *nr_dict_attr_byvalue(unsigned int attr,
					 unsigned int vendor);

/** Look up an attribute in the dictionaries.  \ingroup dict
 *
 *  The dictionary mapping contains information about the attribute,
 *  such as printable name, data type (ipaddr, integer, etc), and
 *  various other things used to encode/decode the attribute in a
 *  packet.
 *
 *  \attention There is usually no need to call this function.
 *
 * @param[in] name    Name of the attribute
 * @return    NULL for "not found", or a pointer to the attribute mapping.
 */
extern const DICT_ATTR *nr_dict_attr_byname(const char *name);

/** Converts raw data to a ::DICT_ATTR structure.  \ingroup dict
 *
 *  It is called when the library is asked to decode an attribute
 *  which is not in the pre-defined dictionaries.
 *
 *  \attention There is usually no need to call this function.
 *
 * @param[in,out] da      The ::DICT_ATTR structure to initialize
 * @param[in]     attr    The attribute number
 * @param[in]     vendor  The vendor number
 * @param[in]     buffer  The buffer where the name of the attribute is stored
 * @param[in]     bufsize Size of the buffer
 * @return    <0 for error, 0 for success
 */
extern int nr_dict_attr_2struct(DICT_ATTR *da,
				unsigned int attr, unsigned int vendor,
				char *buffer, size_t bufsize);

/**  Unused. \ngroup dict
 *
 */
extern const DICT_VALUE *nr_dict_value_byattr(unsigned int attr,
					unsigned int vendor,
					int value);

/**  Unused. \ngroup dict
 *
 */
const DICT_VALUE *nr_dict_value_byname(unsigned int attr,
				 unsigned int vendor,
				 const char *name);

/** Look up a vendor in the dictionaries.  \ingroup dict
 *
 *  The dictionary mapping contains information about the vendor, such
 *  as printable name, VSA encoding method, etc.
 *
 *  \attention There is usually no need to call this function.
 *  Applications do not need access to low-level RADIUS protocol
 *  information.
 *
 * @param[in] name    Name of the vendor.
 * @return    NULL for "not found", or a pointer to the vendor mapping.
 */
extern int nr_dict_vendor_byname(const char *name);

/** Look up an vendor in the dictionaries.  \ingroup dict
 *
 *  The dictionary mapping contains information about the vendor, such
 *  as printable name, VSA encoding method, etc.
 *
 *  \attention There is usually no need to call this function.
 *
 * @param[in] vendor Vendor-Id (or Private Enterprise code) for the vendor.
 * @return    NULL for "not found", or a pointer to the vendor mapping.
 */
extern const DICT_VENDOR *nr_dict_vendor_byvalue(unsigned int vendor);

/**  Static array of known vendors.  \ingroup dict
 *
 *  \attention This structure should only be accessed by internal RADIUS library
 *  functions.
 */
extern const DICT_VENDOR nr_dict_vendors[];

/** The number of attribute definitions in the dictionary.  \ingroup dict
 *
 *  This number is guaranteed to be at least 256, for speed.
 *
 *  \attention This variable should only be accessed by internal RADIUS library
 *  functions.
 */
extern const int nr_dict_num_attrs;

/** The list of attribute definitions.  \ingroup dict
 *
 *  The "standard" RFC attributes are located in the first 256
 *  entries.  Standard attributes without a dictionary definition are
 *  given an empty entry.
 *
 *  The attributes are orderd by (vendor, attribute), in increasing
 *  order.  This allows the dictionary lookups to find attributes by a
 *  binary search.
 *
 *  \attention This variable should only be accessed by internal RADIUS library
 *  functions.
 */
extern const DICT_ATTR nr_dict_attrs[];

/** The number of attributes with names.  \ingroup dict
 *
 *  \attention This variable should only be accessed by internal RADIUS library
 *  functions.
 */
extern const int nr_dict_num_names;

/** The list of attribute definitions, organized by name.  \ingroup dict
 *
 *  The attributes are orderd by name (case insensitive), in
 *  increasing order.  This allows the dictionary lookups to find
 *  attributes by a binary search.
 *
 *  \attention This variable should only be accessed by internal RADIUS library
 *  functions.
 */
extern const DICT_ATTR const *nr_dict_attr_names[];

/** Static array containing names the RADIUS_PACKET::code field.  \ingroup dict
 *
 *  The names are hard-coded and not in any dictionary because they do
 *  not change.
 *
 *  The names are exported because they may be useful in your
 *  application.  Packet codes which are not handled by the library
 *  have NULL for their names.
 */
extern const char *nr_packet_codes[RS_MAX_PACKET_CODE + 1];

/** Verifies that a packet is "well formed".  \ingroup packet
 *
 *  This function performs basic validation to see if the packet is
 *  well formed.  It is automatically called by nr_packet_decode().
 *
 * @param[in] packet      A pointer to the ::RADIUS_PACKET data.
 * @return                <0 means malformed, >= 0 means well-formed.
 */
extern int nr_packet_ok(RADIUS_PACKET *packet);

/** Verifies that a packet is "well formed".  \ingroup packet
 *
 *  This function performs basic validation to see if the packet is
 *  well formed.  You should normally use nr_packet_ok() instead of
 *  this function.
 *
 * @param[in] data        A pointer to the raw packet data.
 * @param[in] sizeof_data The length of the raw packet data
 * @return                <0 means malformed, >= 0 means well-formed.
 */
extern int nr_packet_ok_raw(const uint8_t *data, size_t sizeof_data);

/** Encodes a packet.  \ingroup packet
 *
 *  This function encodes a packet using the fields of the
 *  ::RADIUS_PACKET structure.  The RADIUS_PACKET::code and
 *  RADIUS_PACKET::id fields are used to fill in the relevant fields
 *  of the raw (encoded) packet.  The RADIUS_PACKET::vps list is
 *  walked to encode the attributes.  The packet is signed, if
 *  required.
 *
 *  The raw packet is placed into the RADIUS_PACKET::data field, up to
 *  RADIUS_PACKET::sizeof_data bytes.  the RADIUS_PACKET::length field
 *  is updated with the length of the raw packet.  This field is
 *  always less than, or equal to, the RADIUS_PACKET::size_data field.
 *  If there is insufficient room to store all of the attributes, then
 *  some attributes are silently discarded.
 *
 *  The RADIUS_PACKET::vector field is either calculated as part of
 *  the signing process, or is initialized by this function to be a
 *  random sequence of bytes.  That field should therefore be left
 *  alone by the caller.
 *
 *  When the encoding has been successful, it sets the
 *  RADIUS_PACKET::encoded field to non-zero.
 *
 *  In addition, all required attribute "encryption" is performed.
 *
 *  User-Password.  The vp_strvalue field is assumed to contain the
 *  "clear-text" version of the password.  The encrypted version is
 *  calculated, and placed in the packet.
 *
 *  CHAP-Password.  The vp_strvalue field is assumed to contain the
 *  "clear-text" version of the password.  The encrypted version is
 *  calculated, and placed in the packet.  If the RADIUS_PACKET::vps
 *  list contains a CHAP-Challenge attribute, it is used.  Otherwise
 *  the RADIUS_PACKET::vector field is used a the challenge.
 *
 *  Message-Authenticator.  The contents of the Message-Authenticator
 *  in the RADIUS_PACKET::vps list are ignored.  Instead, a
 *  "place-holder" is put into the packt.  Tthe correct value is
 *  calculated and placed into the packet by nr_packet_sign().
 *
 *  The RADIUS_PACKET::vps list is left untouched by this function,
 *  even when attribute encryption or signing is performed.  Any
 *  VALUE_PAIR structures can therefore be taken from static "const"
 *  variables.
 *
 * @param[in] packet   The RADIUS packet to encode.
 * @param[in] original The original request, when encoding a response.
 * @return             <0 on error, >= 0 on success.
 */
extern int nr_packet_encode(RADIUS_PACKET *packet, const RADIUS_PACKET *original);

/** Decodes a packet.  \ingroup packet
 *
 *  This function decodes a packet from the RADIUS_PACKET::data field
 *  into a sequence of ::VALUE_PAIR structures in the
 *  RADIUS_PACKET::vps list.
 *
 * @param[in] packet   The RADIUS packet to decode.
 * @param[in] original The original request, when decoding a response.
 * @return             <0 on error, >= 0 on success.
 */
extern int nr_packet_decode(RADIUS_PACKET *packet, const RADIUS_PACKET *original);

/** Signs a packet so that it can be sent.  \ingroup packet
 *
 * This function calculates the Message-Authenticator (if required),
 * and signs the packet.
 *
 * @param[in] packet   The RADIUS packet to sign.
 * @param[in] original The original request, when signing a response.
 * @return             <0 on error, >= 0 on success.
 */
extern int nr_packet_sign(RADIUS_PACKET *packet, const RADIUS_PACKET *original);

/** Verifies that a packet is well-formed and contains the correct signature.  \ingroup packet
 *
 *  If "original" is specified, it also verifies that the packet is a
 *  response to the original request, and that it has the correct
 *  signature.
 *
 * @param[in] packet   The RADIUS packet to verify.
 * @param[in] original The original request, when verifying a response.
 * @return             <0 on error, >= 0 on success.
 */
extern int nr_packet_verify(RADIUS_PACKET *packet,
			    const RADIUS_PACKET *original);

/** Pretty-prints a hex dump of a RADIUS packet.  \ingroup packet print
 *
 *  This function is available only in debugging builds of the
 *  library.  It is useful during development, but should not be used
 *  in a production system.
 *
 *  The packet headers are printed individually, and each attribute is
 *  printed as "type length data..."
 *
 * @param[in] packet   The RADIUS packet to print
 */
extern void nr_packet_print_hex(RADIUS_PACKET *packet);


/** Return the given number of random bytes.  \ingroup custom
 *
 * This function should be replaced by one that is specific to your
 * system.
 *
 *  This is a wrapper function which enables the library to be more
 *  portable.
 *
 * @param[in] data      Location where the random bytes will be stored
 * @param[in] data_len  Number of bytes to store
 * @return              <0 on error, or the total number of bytes stored.
 */
extern ssize_t nr_rand_bytes(uint8_t *data, size_t data_len);

/** Return a random 32-bit integer.  \ingroup custom
 *
 * This function should be replaced by one that is specific to your
 * system.  The version supplied here just calls nr_rand_bytes() each
 * time, which is slow.
 *
 *  This is a wrapper function which enables the library to be more
 *  portable.
 *
 * @return An unsigned 32-bit random integer.
 */
extern uint32_t nr_rand(void);

/** Add a time to the given ::struct timeval.  \ingroup custom
 *
 *  This is a wrapper function which enables the library to be more
 *  portable.
 *
 *  @param[in,out] t       The timeval to which the time is added.
 *  @param[in]     seconds Time in seconds to add
 *  @param[in]     usec    Time in microseconds to add
 */
extern void nr_timeval_add(struct timeval *t, unsigned int seconds,
			   unsigned int usec);

/** Compare two times.  \ingroup custom
 *
 *  This is a wrapper function which enables the library to be more
 *  portable.
 *
 * @param[in] a One timeval
 * @param[in] b Another one
 * @return a <=> b
 */
extern int nr_timeval_cmp(const struct timeval *a, const struct timeval *b);

/** Initializes an ::nr_server_t.  \ingroup id
 *
 * @param[in,ut] s      The ::nr_server_t to initialize
 * @param[in]    code   The packet code used for packets sent to this server
 * @param[in]    secret The shared secret used for packet sent to this server
 * @return <0 for error, >= 0 for success
 */
extern int nr_server_init(nr_server_t *s, int code, const char *secret);

/** Closes an ::nr_server_t data structure.  \ingroup id
 *
 *  Ensures that all IDs are free, and closes the socket.
 *
 * @param[in] s      The server structure to close.
 * @return <0 for error, 0 for success
 */
extern int nr_server_close(const nr_server_t *s);

/** Allocate a RADIUS_PACKET::id value for sending a packet to a server. \ingroup id
 *
 * This function allocates a RADIUS_PACKET::id from the ::nr_server_t
 * structure.  It also fills in the RADIUS_PACKET::sockfd,
 * RADIUS_PACKET::code, and RADIUS_PACKET::dst fields.
 *
 * @param[in] s      The server structure which tracks the ID
 * @param[in] packet The packet which needs an ID
 * @return <0 for error, 0 for success
 */
extern int nr_server_id_alloc(nr_server_t *id, RADIUS_PACKET *packet);

/** Re-allocate a RADIUS_PACKET::id value for sending a packet to a server. \ingroup id
 *
 *  It is used when retransmitting an Accounting-Request packet to a
 *  server, after updating the Acct-Delay-Time field.  The "realloc"
 *  name means that the new ID is allocated, and is guaranteed to be
 *  different from the old one.
 *
 * @param[in] s      The server structure which tracks the ID
 * @param[in] packet The packet which needs a new ID
 * @return <0 for error, 0 for success
 */
extern int nr_server_id_realloc(nr_server_t *id, RADIUS_PACKET *packet);

/** Free a RADIUS_PACKET::id value after sending a packet to a server. \ingroup id
 *
 * @param[in] s      The server structure which tracks the ID
 * @param[in] packet The packet which has an ID, and wants to free it
 * @return <0 for error, 0 for success
 */
extern int nr_server_id_free(nr_server_t *id, RADIUS_PACKET *packet);


/** Allocates a packet using malloc(), and initializes it. \ingroup id
 *
 * @param[in] s             The server structure
 * @param[in,out] packet_p  Pointer to the ::RADIUS_PACKET to be allocated
 * @return <0 for error, 0 for success
 */
extern int nr_server_packet_alloc(const nr_server_t *s, RADIUS_PACKET **packet_p);

/**  Record a humanly readable error message. \ingroup error
 *
 *  \attention This structure should only be accessed by internal
 *  RADIUS library functions.
 *
 * @param[in] fmt   The format to use.
 */
extern void nr_strerror_printf(const char *fmt, ...);

#ifndef NDEBUG
#define nr_debug_error nr_strerror_printf /** \ingroup error */
#else
#define nr_debug_error if (0) nr_strerror_printf
#endif

/**  Encrypts or decrypts a User-Password attribute. \ingroup internal
 *
 *  \attention This structure should only be accessed by internal
 *  RADIUS library functions.
 *
 * @param[out] output   Buffer where the password is stored
 * @param[out] outlen   Size of the output buffer
 * @param[in]  input    Input buffer with password
 * @param[in]  inlen    Length of the input buffer
 * @param[in]  secret   The shared secret
 * @param[in]  vector   Authentication vector
 * @return <0 on error, or the length of data in "output"
 */
extern ssize_t nr_password_encrypt(uint8_t *output, size_t outlen,
				   const uint8_t *input, size_t inlen,
				   const char *secret, const uint8_t *vector);

/**  Encrypts a Tunnel-Password attribute. \ingroup internal
 *
 *  \attention This structure should only be accessed by internal
 *  RADIUS library functions.
 *
 * @param[out] output   Buffer where the password is stored
 * @param[out] outlen   Size of the output buffer
 * @param[in]  input    Input buffer with password
 * @param[in]  inlen    Length of the input buffer
 * @param[in]  secret   The shared secret
 * @param[in]  vector   Authentication vector
 * @return <0 on error, or the length of data in "output"
 */
extern ssize_t nr_tunnelpw_encrypt(uint8_t *output, size_t outlen,
				   const uint8_t *input, size_t inlen,
				   const char *secret, const uint8_t *vector);

/**  Decrypts a Tunnel-Password attribute. \ingroup internal
 *
 *
 *  \attention This structure should only be accessed by internal
 *  RADIUS library functions.
 *
 * @param[out] output   Buffer where the password is stored
 * @param[out] outlen   Size of the output buffer
 * @param[in]  input    Input buffer with password
 * @param[in]  inlen    Length of the input buffer
 * @param[in]  secret   The shared secret
 * @param[in]  vector   Authentication vector
 * @return <0 on error, or the length of data in "output"
 */
extern ssize_t nr_tunnelpw_decrypt(uint8_t *output, size_t outlen,
				   const uint8_t *input, size_t inlen,
				   const char *secret, const uint8_t *vector);

/**  Calculates an HMAC-MD5. \ingroup internal
 *
 * @param[in] data      Data to be hashed
 * @param[in] data_len  Length of data to be hashed
 * @param[in] key       Key for the HMAC
 * @param[in] key_len   Length of the key
 * @param[out] digest
 */
extern void nr_hmac_md5(const uint8_t *data, size_t data_len,
			const uint8_t *key, size_t key_len,
			uint8_t digest[16]);

/** Checks if a TLV is properly formatted. \ingroup internal
 *
 *  \attention This structure should only be accessed by internal
 *  RADIUS library functions.
 *
 * @param[in] data      Data to check
 * @param[in] length    Length of the data field
 * @param[in] dv_type   Length of the TLV "type" field
 * @param[in] dv_length Length of the TLV "length" field
 * @return             <0 on error, 0 for "TLV is OK"
 */
extern int nr_tlv_ok(const uint8_t *data, size_t length,
		      size_t dv_type, size_t dv_length);

/** A callback function used by nr_packet_walk().  \ingroup packet
 *
 *  The function should return 0 on success (i.e. keep walking), and
 *  otherwise a negative number indicating an error code
 *  (::nr_error_t).  That negative number will be used as the return
 *  code for nr_packet_walk().
 */
typedef int (*nr_packet_walk_func_t)(void *, const DICT_ATTR *, const uint8_t *, size_t);

/** Walks over all attributes in a packet. \ingroup packet
 *
 *  This function is an iterator which calls a user-supplied callback
 *  function for each attribute in the packet.  It should be used
 *  instead of manually walking over the attributes.  There are a
 *  number of odd corner cases when handling Vendor-Specific
 *  attributes, and it is easy to get those corner cases wrong.
 *
 *  This function iterates over *all* attributes, including nested
 *  VSAs.  That is its main value.
 *
 *  Encrypted attributes such as User-Password are not decrypted.
 *
 * @param[in] packet    The packet containing the data
 * @param[in] ctx       A user-supplied context.  May be NULL
 * @param[in] callback  The callback function where the information is passed.
 *
 * @return <0 for error,
 *          0 for success.
 */
extern int nr_packet_walk(RADIUS_PACKET *packet, void *ctx,
			  nr_packet_walk_func_t callback);

/** Initialize a packet
 *
 *  If original is specified, the packet is initialized as a response
 *  to the original request.
 *
 * @param[in,out] packet  The packet to initialize
 * @param[in] original    The original request (if any) to use as a template
 * @param[in] secret      Shared secret
 * @param[in] code        RADIUS Code field.
 * @param[in] data        Buffer where packets will be stored (RADIUS_PACKET::data)
 * @param[in] sizeof_data Size of buffer (RADIUS_PACKET::sizeof_data)
 * @return  <0 on error, 0 for success.
 */
extern int nr_packet_init(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
			  const char *secret, int code,
			  void *data, size_t sizeof_data);

/** Add one attribute to the packet.
 *
 *  This function can be used to add "raw" data to a packet.  It
 *  allows the caller to extend the RADIUS packet without using a
 *  ::VALUE_PAIR data structure.
 *
 *  Some attributes are handled specially by this function.
 *
 *  EAP-Message.  This attribute is automatically split into 253-octet
 *  chunks.
 *
 *  User-Password, CHAP-Password, and Message-Authenticator.  These
 *  attributes are automatically encrypted, as is done by
 *  nr_packet_encode().
 *
 * @param[in] packet   The packet to edit
 * @param[in] original The original request (if any)
 * @param[in] da       Pointer to the attribute definition
 * @param[in] data     Data to append to the packet
 * @param[in] data_len Length of data to append to the packet
 *
 * @return <0 for error, >= 0 for "successfully appended data"
 *  The function returns the number of octets appended to the packet.
 */
extern ssize_t nr_packet_attr_append(RADIUS_PACKET *packet,
				     const RADIUS_PACKET *original,
				     const DICT_ATTR *da,
				     const void *data, size_t data_len);


/** Encodes any ::VALUE_PAIR into an attribute.  \ingroup attr
 *
 *  This function can be called for any ::VALUE_PAIR.  It will examine
 *  that structure, and call one of nr_vp2rfc() or nr_vp2vsa() as
 *  necessary.
 *
 * \attention This function should not be called.
 *
 * @param[in] packet   Where to place the encoded attribute.
 * @param[in] original The original request (optional), if "packet" is a response
 * @param[in,out] pvp  The ::VALUE_PAIR to encode.  On any return >=0, it is updated to point to the "next" ::VALUE_PAIR which should be encoded.
 * @param[in] data     Where the attribute is to be encoded.
 * @param[in] room     How many octets are available for attribute encoding.
 *
 * @return <0 for error, or the number of octets used to encode the attribute.
 */
extern ssize_t nr_vp2attr(const RADIUS_PACKET *packet,
		      const RADIUS_PACKET *original,
		      const VALUE_PAIR **pvp, uint8_t *data, size_t room);

/** Encodes an RFC "standard" ::VALUE_PAIR into an attribute.  \ingroup attr
 *
 *  \attention This function should not be called.
 *
 * @param[in] packet   Where to place the encoded attribute.
 * @param[in] original The original request (optional), if "packet" is a response
 * @param[in,out] pvp  The ::VALUE_PAIR to encode.  On any return >=0, it is updated to point to the "next" ::VALUE_PAIR which should be encoded.
 * @param[in] data      Where the attribute is to be encoded.
 * @param[in] room     How many octets are available for attribute encoding.
 *
 * @return <0 for error, or the number of octets used to encode the attribute.
 */
extern ssize_t nr_vp2rfc(const RADIUS_PACKET *packet,
		     const RADIUS_PACKET *original,
		     const VALUE_PAIR **pvp,
		     uint8_t *data, size_t room);

/** Decodes any attribute into a ::VALUE_PAIR.  \ingroup attr
 *
 *  \attention This function should not be called.
 *
 * @param[in] packet   The packet containing the attribute to be decoded.
 * @param[in] original The original request (optional), if "packet" is a response
 * @param[out] pvp     Where to place the decoded ::VALUE_PAIR.  On any return >=0, it is updated to point to the ::VALUE_PAIR which was decoded from the packet.
 * @param[in] data     Where the attribute is to be encoded.
 * @param[in] length   How many octets are available for attribute decoding.
 *
 * @return <0 for error, or the number of octets used to decode the attribute.
 */
extern ssize_t nr_attr2vp(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
			    const uint8_t *data, size_t length,
			    VALUE_PAIR **pvp);

/** Decodes an RFC "standard" attribute into a ::VALUE_PAIR.  \ingroup attr
 *
 *  \attention This function should not be called.
 *
 * @param[in] packet   The packet containing the attribute to be decoded.
 * @param[in] original The original request (optional), if "packet" is a response
 * @param[out] pvp     Where to place the decoded ::VALUE_PAIR.  On any return >=0, it is updated to point to the ::VALUE_PAIR which was decoded from the packet.
 * @param[in] data     Where the attribute is to be encoded.
 * @param[in] length   How many octets are available for attribute decoding.
 *
 * @return <0 for error, or the number of octets used to decode the attribute.
 */
extern ssize_t nr_attr2vp_rfc(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp);

/** Decodes a Vendor-Specific attribute into a ::VALUE_PAIR.  \ingroup attr
 *
 *  \attention This function should not be called.
 *
 * @param[in] packet   The packet containing the attribute to be decoded.
 * @param[in] original The original request (optional), if "packet" is a response
 * @param[out] pvp     Where to place the decoded ::VALUE_PAIR.  On any return >=0, it is updated to point to the ::VALUE_PAIR which was decoded from the packet.
 * @param[in] data     Where the attribute is to be encoded.
 * @param[in] length   How many octets are available for attribute decoding.
 *
 * @return <0 for error, or the number of octets used to decode the attribute.
 */
extern ssize_t nr_attr2vp_vsa(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp);

/** Decodes an attribute with an unexpected length into a ::VALUE_PAIR.  \ingroup attr
 *
 *  \attention This function should not be called.
 *
 * @param[in] packet   The packet containing the attribute to be decoded.
 * @param[in] original The original request (optional), if "packet" is a response
 * @param[out] pvp     Where to place the decoded ::VALUE_PAIR.  On any return >=0, it is updated to point to the ::VALUE_PAIR which was decoded from the packet.
 * @param[in] data     Where the attribute is to be encoded.
 * @param[in] length   How many octets are available for attribute decoding.
 *
 * @return <0 for error, or the number of octets used to decode the attribute.
 */
extern ssize_t nr_attr2vp_raw(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp);

/** Encodes a Vendor-Specific ::VALUE_PAIR into an attribute.
 *
 *  \attention This function should not be called.
 *
 * @param[in] packet   Where to place the encoded attribute.
 * @param[in] original The original request (optional), if "packet" is a response
 * @param[in,out] pvp  The ::VALUE_PAIR to encode.  On any return >=0, it is updated to point to the "next" ::VALUE_PAIR which should be encoded.
 * @param[in] data     Where the attribute is to be encoded.
 * @param[in] room     How many octets are available for attribute encoding.
 *
 * @return <0 for error, or the number of octets used to encode the attribute.
 */
extern ssize_t nr_vp2vsa(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		     const VALUE_PAIR **pvp, uint8_t *data,
		     size_t room);

/** Returns raw data from the RADIUS packet, for a given attribute. \ingroup attr
 *
 *  This function can be called repeatedly to find all instances of a
 *  given attribute.  The first time it is called, the "start"
 *  parameter should be zero.  If the function returns a non-zero
 *  positive number, it means that there *may* be more attributes
 *  available.  The returned value should be then passed via the
 *  "start" option in any subsequent calls to the function.
 *
 *  This function should be called by an application when it wants
 *  access to data which is not in the pre-defined dictionaries.
 *
 * @param[in] packet   The packet containing the attribute.
 * @param[in] start    Where in the packet we start searching for the attribute.
 * @param[in] attr     Value of the attribute to search for
 * @param[in] vendor   Value of the vendor (use 0 for IETF attributes)
 * @param[out] pdata   Pointer to the data.  If no data was found, the pointer is unchanged.
 * @param[out] plength  Length of the data.  If no data was found, the value pointed to is unchanged.
 *
 * @return <0 for error,
 *          0 for "no attribute found, stop searching"
 *         >0 offset where the attribute was found.
 */
extern ssize_t nr_attr2data(const RADIUS_PACKET *packet, ssize_t start,
			     unsigned int attr, unsigned int vendor,
			     const uint8_t **pdata, size_t *plength);

/**  Pretty-print the entire ::VALUE_PAIR \ingroup print
 *
 *  All data is printed in ASCII format.  The data type of "octets" is
 *  printed as a hex string (e.g. 0xabcdef01...).  The data type of
 *  "ipaddr" is printed as a dotted-quad (e.g. 192.0.2.15).
 *
 *  The format is "Attribute-Name = value"
 *
 * @param[out] buffer  Where the printable version of the ::VALUE_PAIR is stored
 * @param[in]  bufsize size of the output buffer
 * @param[in]  vp      ::VALUE_PAIR to print
 * @return   length of data in buffer
 */
extern size_t nr_vp_snprintf(char *buffer, size_t bufsize, const VALUE_PAIR *vp);

/**  Pretty-print the VALUE_PAIR::data field \ingroup print
 *
 *  Prints the value of a ::VALUE_PAIR, without the name or "=" sign.
 *
 * @param[out] buffer  Where the printable version of the ::VALUE_PAIR is stored
 * @param[in]  bufsize size of the output buffer
 * @param[in]  vp      ::VALUE_PAIR to print
 * @return   length of data in buffer
 */
extern size_t nr_vp_snprintf_value(char *buffer, size_t bufsize, const VALUE_PAIR *vp);

/** Prints a list of :VALUE_PAIR structures to the given output. \ingroup print
 *
 * @param[in] fp   Where to print the results
 * @param[in] vps  Linked list of ::VALUE_PAIR to print
 */
extern void nr_vp_fprintf_list(FILE *fp, const VALUE_PAIR *vps);

/** Scan a string into a ::VALUE_PAIR.  The counterpart to
 * nr_vp_snprintf_value() \ingroup print
 *
 * @param[in] string  Printable version of the ::VALUE_PAIR
 * @param[out] pvp    Newly allocated ::VALUE_PAIR
 * @return <0 on error, 0 for success.
 */
extern int nr_vp_sscanf(const char *string, VALUE_PAIR **pvp);

/** Scan the data portion of a ::VALUE_PAIR.  The counterpart to
 * nr_vp_snprintf_value() \ingroup print
 *
 * @param[in,out] vp    The ::VALUE_PAIR where the data will be stored
 * @param[in]     value The string version of the data to be parsed
 * @return             <0 on error, >=0 for the number of characters parsed in value.
 */
extern ssize_t nr_vp_sscanf_value(VALUE_PAIR *vp, const char *value);

#if defined(__GNUC__)
# define PRINTF_LIKE(n) __attribute__ ((format(printf, n, n+1)))
# define NEVER_RETURNS __attribute__ ((noreturn))
# define UNUSED __attribute__ ((unused))
# define BLANK_FORMAT " "	/* GCC_LINT whines about empty formats */
#else

/** Macro used to quiet compiler warnings inside of the library. \ingroup build
 *
 */
# define PRINTF_LIKE(n)

/** Macro used to quiet compiler warnings inside of the library. \ingroup build
 *
 */
# define NEVER_RETURNS

/** Macro used to quiet compiler warnings inside of the library. \ingroup build
 *
 */
# define UNUSED

/** Macro used to quiet compiler warnings inside of the library. \ingroup build
 *
 */
# define BLANK_FORMAT ""
#endif

#endif /* _RADIUS_CLIENT_H_ */
