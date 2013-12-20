/** \file radsec.h
    \brief Public interface for libradsec.  */

/* Copyright 2010-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#ifndef _RADSEC_RADSEC_H_
#define _RADSEC_RADSEC_H_ 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

enum rs_error_code {
    RSE_OK = 0,
    RSE_NOMEM = 1,
    RSE_NOSYS = 2,
    RSE_INVALID_CTX = 3,
    RSE_INVALID_CONN = 4,
    RSE_CONN_TYPE_MISMATCH = 5,
    RSE_BADADDR = 7,
    RSE_NOPEER = 8,
    RSE_EVENT = 9,		/* libevent error.  */
    RSE_SOCKERR = 10,
    RSE_CONFIG = 11,
    RSE_BADAUTH = 12,
    RSE_INTERNAL = 13,
    RSE_SSLERR = 14,		/* OpenSSL error.  */
    RSE_INVALID_PKT = 15,
    RSE_TIMEOUT_CONN = 16,	/* Connection timeout.  */
    RSE_INVAL = 17,		/* Invalid argument.  */
    RSE_TIMEOUT_IO = 18,	/* I/O timeout.  */
    RSE_TIMEOUT = 19,		/* High level timeout.  */
    RSE_DISCO = 20,
    RSE_INUSE = 21,
    RSE_PACKET_TOO_SMALL = 22,
    RSE_PACKET_TOO_LARGE = 23,
    RSE_ATTR_OVERFLOW = 24,
    RSE_ATTR_TOO_SMALL = 25,
    RSE_ATTR_TOO_LARGE = 26,
    RSE_ATTR_UNKNOWN = 27,
    RSE_ATTR_BAD_NAME = 28,
    RSE_ATTR_VALUE_MALFORMED = 29,
    RSE_ATTR_INVALID = 30,
    RSE_TOO_MANY_ATTRS = 31,
    RSE_ATTR_TYPE_UNKNOWN = 32,
    RSE_MSG_AUTH_LEN = 33,
    RSE_MSG_AUTH_WRONG = 34,
    RSE_REQUEST_REQUIRED = 35,
    RSE_INVALID_REQUEST_CODE = 36,
    RSE_AUTH_VECTOR_WRONG = 37,
    RSE_INVALID_RESPONSE_CODE = 38,
    RSE_INVALID_RESPONSE_ID = 39,
    RSE_INVALID_RESPONSE_SRC = 40,
    RSE_NO_PACKET_DATA = 41,
    RSE_VENDOR_UNKNOWN = 42,
    RSE_CRED = 43,
    RSE_CERT = 44,
    RSE_MAX = RSE_CERT
};

enum rs_conn_type {
    RS_CONN_TYPE_NONE = 0,
    RS_CONN_TYPE_UDP,
    RS_CONN_TYPE_TCP,
    RS_CONN_TYPE_TLS,
    RS_CONN_TYPE_DTLS,
};
typedef unsigned int rs_conn_type_t;

typedef enum rs_attr_type_t {
    RS_TYPE_INVALID = 0,		/**< Invalid data type */
    RS_TYPE_STRING,      		/**< printable-text */
    RS_TYPE_INTEGER,     		/**< a 32-bit unsigned integer */
    RS_TYPE_IPADDR,      		/**< an IPv4 address */
    RS_TYPE_DATE,			/**< a 32-bit date, of seconds since January 1, 1970 */
    RS_TYPE_OCTETS,			/**< a sequence of binary octets */
    RS_TYPE_IFID,	     		/**< an Interface Id */
    RS_TYPE_IPV6ADDR,			/**< an IPv6 address */
    RS_TYPE_IPV6PREFIX,			/**< an IPv6 prefix */
    RS_TYPE_BYTE,			/**< an 8-bit integer */
    RS_TYPE_SHORT,			/**< a 16-bit integer */
} rs_attr_type_t;

#define	PW_ACCESS_REQUEST		1
#define	PW_ACCESS_ACCEPT		2
#define	PW_ACCESS_REJECT		3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6
#define PW_PASSWORD_REQUEST		7
#define PW_PASSWORD_ACK			8
#define PW_PASSWORD_REJECT		9
#define	PW_ACCOUNTING_MESSAGE		10
#define PW_ACCESS_CHALLENGE		11
#define PW_STATUS_SERVER		12
#define PW_STATUS_CLIENT		13
#define PW_DISCONNECT_REQUEST		40
#define PW_DISCONNECT_ACK		41
#define PW_DISCONNECT_NAK		42
#define PW_COA_REQUEST			43
#define PW_COA_ACK			44
#define PW_COA_NAK			45

#if defined (__cplusplus)
extern "C" {
#endif

/* Data types.  */
struct rs_context;		/* radsec-impl.h */
struct rs_connection;		/* radsec-impl.h */
struct rs_packet;		/* radsec-impl.h */
struct rs_conn;			/* radsec-impl.h */
struct rs_error;		/* radsec-impl.h */
struct rs_peer;			/* radsec-impl.h */
struct radius_packet;		/* <radius/client.h> */
struct value_pair;		/* <radius/client.h> */
struct event_base;		/* <event2/event-internal.h> */

typedef void *(*rs_calloc_fp) (size_t nmemb, size_t size);
typedef void *(*rs_malloc_fp) (size_t size);
typedef void (*rs_free_fp) (void *ptr);
typedef void *(*rs_realloc_fp) (void *ptr, size_t size);
struct rs_alloc_scheme {
    rs_calloc_fp calloc;
    rs_malloc_fp malloc;
    rs_free_fp free;
    rs_realloc_fp realloc;
};

typedef void (*rs_conn_connected_cb) (void *user_data /* FIXME: peer? */ );
typedef void (*rs_conn_disconnected_cb) (void *user_data /* FIXME: reason? */ );
typedef void (*rs_conn_packet_received_cb) (struct rs_packet *packet,
					    void *user_data);
typedef void (*rs_conn_packet_sent_cb) (void *user_data);
struct rs_conn_callbacks {
    /** Callback invoked when the connection has been established.  */
    rs_conn_connected_cb connected_cb;
    /** Callback invoked when the connection has been torn down.  */
    rs_conn_disconnected_cb disconnected_cb;
    /** Callback invoked when a packet was received.  */
    rs_conn_packet_received_cb received_cb;
    /** Callback invoked when a packet was successfully sent.  */
    rs_conn_packet_sent_cb sent_cb;
};

typedef struct value_pair rs_avp;
typedef const struct value_pair rs_const_avp;

/* Function prototypes.  */

/*************/
/* Context.  */
/*************/
/** Create a context.  Freed by calling \a rs_context_destroy.  Note
    that the context must not be freed before all other libradsec
    objects have been freed.

    If support for POSIX threads was detected at configure and build
    time \a rs_context_create will use mutexes to protect multiple
    threads from stomping on each other in OpenSSL.

    \a ctx Address of pointer to a struct rs_context.  This is the
    output of this function.

    \return RSE_OK (0) on success, RSE_SSLERR on TLS library
    initialisation error and RSE_NOMEM on out of memory.  */
int rs_context_create(struct rs_context **ctx);

/** Free a context.  Note that the context must not be freed before
    all other libradsec objects have been freed.  */
void rs_context_destroy(struct rs_context *ctx);

/** Set allocation scheme to use.  \a scheme is the allocation scheme
    to use, see \a rs_alloc_scheme.  \return On success, RSE_OK (0) is
    returned.  On error, !0 is returned and a struct \a rs_error is
    pushed on the error stack for the context.  The error can be
    accessed using \a rs_err_ctx_pop.  */
int rs_context_set_alloc_scheme(struct rs_context *ctx,
				struct rs_alloc_scheme *scheme);

/** Read configuration file. \a config_file is the path of the
    configuration file to read.  \return On success, RSE_OK (0) is
    returned.  On error, !0 is returned and a struct \a rs_error is
    pushed on the error stack for the context.  The error can be
    accessed using \a rs_err_ctx_pop.  */
int rs_context_read_config(struct rs_context *ctx, const char *config_file);

/****************/
/* Connection.  */
/****************/
/** Create a connection.  \a conn is the address of a pointer to an \a
    rs_connection, the output.  Free the connection using \a
    rs_conn_destroy.  Note that a connection must not be freed before
    all packets associated with the connection have been freed.  A
    packet is associated with a connection when it's created (\a
    rs_packet_create) or received (\a rs_conn_receive_packet).

    If \a config is not NULL it should be the name of a configuration
    found in the config file read in using \a rs_context_read_config.
    \return On success, RSE_OK (0) is returned.  On error, !0 is
    returned and a struct \a rs_error is pushed on the error stack for
    the context.  The error can be accessed using \a
    rs_err_ctx_pop.  */
int rs_conn_create(struct rs_context *ctx,
		   struct rs_connection **conn,
		   const char *config);

/** Not implemented.  */
int rs_conn_add_listener(struct rs_connection *conn,
			 rs_conn_type_t type,
			 const char *hostname,
			 int port);
/** Disconnect connection \a conn.  \return RSE_OK (0) on success, !0
 * on error.  On error, errno is set appropriately.  */
int rs_conn_disconnect (struct rs_connection *conn);

/** Disconnect and free memory allocated for connection \a conn.  Note
    that a connection must not be freed before all packets associated
    with the connection have been freed.  A packet is associated with
    a connection when it's created (\a rs_packet_create) or received
    (\a rs_conn_receive_packet).  \return RSE_OK (0) on success, !0 *
    on error.  On error, errno is set appropriately. */
int rs_conn_destroy(struct rs_connection *conn);

/** Set connection type for \a conn.  */
void rs_conn_set_type(struct rs_connection *conn, rs_conn_type_t type);

/** Not implemented.  */
int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb);

/** Register callbacks \a cb for connection \a conn.  */
void rs_conn_set_callbacks(struct rs_connection *conn,
			   struct rs_conn_callbacks *cb);

/** Remove callbacks for connection \a conn.  */
void rs_conn_del_callbacks(struct rs_connection *conn);

/** Return callbacks registered for connection \a conn.  \return
    Installed callbacks are returned.  */
struct rs_conn_callbacks *rs_conn_get_callbacks(struct rs_connection *conn);

/** Not implemented.  */
int rs_conn_select_peer(struct rs_connection *conn, const char *name);

/** Not implemented.  */
int rs_conn_get_current_peer(struct rs_connection *conn,
			     const char *name,
			     size_t buflen);

/** Special function used in blocking mode, i.e. with no callbacks
    registered.  For any other use of libradsec, a \a received_cb
    callback should be registered using \a rs_conn_set_callbacks.

    If \a req_msg is not NULL, a successfully received RADIUS message
    is verified against it.  If \a pkt_out is not NULL it will upon
    return contain a pointer to an \a rs_packet containing the new
    message.

    \return On error or if the connect (TCP only) or read times out,
    \a pkt_out will not be changed and one or more errors are pushed
    on \a conn (available through \a rs_err_conn_pop).  */
int rs_conn_receive_packet(struct rs_connection *conn,
			   struct rs_packet *request,
			   struct rs_packet **pkt_out);

/** Get the file descriptor associated with connection \a conn.
 * \return File descriptor.  */
int rs_conn_fd(struct rs_connection *conn);

/** Set the timeout value for connection \a conn.  */
void rs_conn_set_timeout(struct rs_connection *conn, struct timeval *tv);

/* Peer -- client and server.  */
int rs_peer_create(struct rs_connection *conn, struct rs_peer **peer_out);
int rs_peer_set_address(struct rs_peer *peer,
			const char *hostname,
			const char *service);
int rs_peer_set_secret(struct rs_peer *peer, const char *secret);
void rs_peer_set_timeout(struct rs_peer *peer, int timeout);
void rs_peer_set_retries(struct rs_peer *peer, int retries);

/************/
/* Packet.  */
/************/
/** Create a packet associated with connection \a conn.  */
int rs_packet_create(struct rs_connection *conn, struct rs_packet **pkt_out);

/** Free all memory allocated for packet \a pkt.  */
void rs_packet_destroy(struct rs_packet *pkt);

/** Send packet \a pkt on the connection associated with \a pkt.
    \a user_data is passed to the \a rs_conn_packet_received_cb callback
    registered with the connection. If no callback is registered with
    the connection, the event loop is run by \a rs_packet_send and it
    blocks until the full packet has been sent. Note that sending can
    fail in several ways, f.ex. if the transmission protocol in use
    is connection oriented (\a RS_CONN_TYPE_TCP and \a RS_CONN_TYPE_TLS)
    and the connection can not be established. Also note that no
    retransmission is done, something that is required for connectionless
    transport protocols (\a RS_CONN_TYPE_UDP and \a RS_CONN_TYPE_DTLS).
    The "request" API with \a rs_request_send can help with this.

    \return On success, RSE_OK (0) is returned. On error, !0 is
    returned and a struct \a rs_error is pushed on the error stack for
    the connection. The error can be accessed using \a rs_err_conn_pop. */
int rs_packet_send(struct rs_packet *pkt, void *user_data);

/** Create a RADIUS authentication request packet associated with
    connection \a conn.  Optionally, User-Name and User-Password
    attributes are added to the packet using the data in \a user_name
    and \a user_pw.  */
int rs_packet_create_authn_request(struct rs_connection *conn,
				   struct rs_packet **pkt,
				   const char *user_name,
				   const char *user_pw);

/** Add a new attribute-value pair to \a pkt. */
int rs_packet_add_avp(struct rs_packet *pkt,
                      unsigned int attr, unsigned int vendor,
                      const void *data, size_t data_len);

/** Append a new attribute to packet \a pkt. Note that this function
    encodes the attribute and therefore might require the secret
    shared with the thought recipient to be set in pkt->rpkt. Note
    also that this function marks \a pkt as already encoded and can
    not be used on packets with non-encoded value-pairs already
    added. */
int
rs_packet_append_avp(struct rs_packet *pkt,
		     unsigned int attribute, unsigned int vendor,
		     const void *data, size_t data_len);

/*** Get pointer to \a pkt attribute value pairs. */
void
rs_packet_avps(struct rs_packet *pkt, rs_avp ***vps);

/*** Get RADIUS packet type of \a pkt. */
unsigned int
rs_packet_code(struct rs_packet *pkt);

/*** Get RADIUS AVP from \a pkt. */
rs_const_avp *
rs_packet_find_avp(struct rs_packet *pkt, unsigned int attr, unsigned int vendor);

/*** Set packet identifier in \a pkt; returns old identifier */
int
rs_packet_set_id (struct rs_packet *pkt, int id);

/************/
/* Config.  */
/************/
/** Find the realm named \a name in the configuration file previoiusly
    read in using \a rs_context_read_config.  */
struct rs_realm *rs_conf_find_realm(struct rs_context *ctx, const char *name);

/***********/
/* Error.  */
/***********/
/** Create a struct \a rs_error and push it on a FIFO associated with
    context \a ctx.  Note: The depth of the error stack is one (1) at
    the moment.  This will change in a future release.  */
int rs_err_ctx_push(struct rs_context *ctx, int code, const char *fmt, ...);
int rs_err_ctx_push_fl(struct rs_context *ctx,
		       int code,
		       const char *file,
		       int line,
		       const char *fmt,
		       ...);
/** Pop the first error from the error FIFO associated with context \a
    ctx or NULL if there are no errors in the FIFO.  */
struct rs_error *rs_err_ctx_pop(struct rs_context *ctx);

/** Create a struct \a rs_error and push it on a FIFO associated with
    connection \a conn.  Note: The depth of the error stack is one (1)
    at the moment.  This will change in a future release.  */
int rs_err_conn_push(struct rs_connection *conn,
		     int code,
		     const char *fmt,
		     ...);
int rs_err_conn_push_fl(struct rs_connection *conn,
			int code,
			const char *file,
			int line,
			const char *fmt,
			...);
/** Pop the first error from the error FIFO associated with connection
    \a conn or NULL if there are no errors in the FIFO.  */
struct rs_error *rs_err_conn_pop(struct rs_connection *conn);

int rs_err_conn_peek_code (struct rs_connection *conn);
void rs_err_free(struct rs_error *err);
char *rs_err_msg(struct rs_error *err);
int rs_err_code(struct rs_error *err, int dofree_flag);

/************/
/* AVPs.    */
/************/
#define rs_avp_is_string(vp)	  (rs_avp_typeof(vp) == RS_TYPE_STRING)
#define rs_avp_is_integer(vp)	  (rs_avp_typeof(vp) == RS_TYPE_INTEGER)
#define rs_avp_is_ipaddr(vp)	  (rs_avp_typeof(vp) == RS_TYPE_IPADDR)
#define rs_avp_is_date(vp)	  (rs_avp_typeof(vp) == RS_TYPE_DATE)
#define rs_avp_is_octets(vp)	  (rs_avp_typeof(vp) == RS_TYPE_OCTETS)
#define rs_avp_is_ifid(vp)	  (rs_avp_typeof(vp) == RS_TYPE_IFID)
#define rs_avp_is_ipv6addr(vp)	  (rs_avp_typeof(vp) == RS_TYPE_IPV6ADDR)
#define rs_avp_is_ipv6prefix(vp)  (rs_avp_typeof(vp) == RS_TYPE_IPV6PREFIX)
#define rs_avp_is_byte(vp)	  (rs_avp_typeof(vp) == RS_TYPE_BYTE)
#define rs_avp_is_short(vp)	  (rs_avp_typeof(vp) == RS_TYPE_SHORT)
#define rs_avp_is_tlv(vp)	  (rs_avp_typeof(vp) == RS_TYPE_TLV)

/**  The maximum length of a RADIUS attribute.
 *
 *  The RFCs require that a RADIUS attribute transport no more than
 *  253 octets of data.  We add an extra byte for a trailing NUL, so
 *  that the VALUE_PAIR::vp_strvalue field can be handled as a C
 *  string.
 */
#define RS_MAX_STRING_LEN         254

/** Free the AVP list \a vps */
void
rs_avp_free(rs_avp **vps);

/** Return the length of AVP \a vp in bytes */
size_t
rs_avp_length(rs_const_avp *vp);

/** Return the type of \a vp */
rs_attr_type_t
rs_avp_typeof(rs_const_avp *vp);

/** Retrieve the attribute and vendor ID of \a vp */
void
rs_avp_attrid(rs_const_avp *vp, unsigned int *attr, unsigned int *vendor);

/** Add \a vp to the list pointed to by \a head */
void
rs_avp_append(rs_avp **head, rs_avp *vp);

/** Find an AVP in \a vp that matches \a attr and \a vendor */
rs_avp *
rs_avp_find(rs_avp *vp, unsigned int attr, unsigned int vendor);

/** Find an AVP in \a vp that matches \a attr and \a vendor */
rs_const_avp *
rs_avp_find_const(rs_const_avp *vp, unsigned int attr, unsigned int vendor);

/** Alloc a new AVP for \a attr and \a vendor */
rs_avp *
rs_avp_alloc(unsigned int attr, unsigned int vendor);

/** Duplicate existing AVP \a vp */
rs_avp *
rs_avp_dup(rs_const_avp *vp);

/** Remove matching AVP from list \a vps */
int
rs_avp_delete(rs_avp **vps, unsigned int attr, unsigned int vendor);

/** Return next AVP in list */
rs_avp *
rs_avp_next(rs_avp *vp);

/** Return next AVP in list */
rs_const_avp *
rs_avp_next_const(rs_const_avp *avp);

/** Return string value of \a vp */
const char *
rs_avp_string_value(rs_const_avp *vp);

/** Set AVP \a vp to string \a str */
int
rs_avp_string_set(rs_avp *vp, const char *str);

/** Return integer value of \a vp */
uint32_t
rs_avp_integer_value(rs_const_avp *vp);

/** Set AVP \a vp to integer \a val */
int
rs_avp_integer_set(rs_avp *vp, uint32_t val);

/** Return IPv4 value of \a vp */
uint32_t
rs_avp_ipaddr_value(rs_const_avp *vp);

/** Set AVP \a vp to IPv4 address \a in */
int
rs_avp_ipaddr_set(rs_avp *vp, struct in_addr in);

/** Return POSIX time value of \a vp */
time_t
rs_avp_date_value(rs_const_avp *vp);

/** Set AVP \a vp to POSIX time \a date */
int
rs_avp_date_set(rs_avp *vp, time_t date);

/** Return constant pointer to octets in \a vp */
const unsigned char *
rs_avp_octets_value_const_ptr(rs_const_avp *vp);

/** Return pointer to octets in \a vp */
unsigned char *
rs_avp_octets_value_ptr(rs_avp *vp);

/** Retrieve octet pointer \a p and length \a len from \a vp */
int
rs_avp_octets_value_byref(rs_avp *vp,
			  unsigned char **p,
			  size_t *len);

/** Copy octets from \a vp into \a buf and \a len */
int
rs_avp_octets_value(rs_const_avp *vp,
		    unsigned char *buf,
		    size_t *len);

/**
 * Copy octets possibly fragmented across multiple VPs
 * into \a buf and \a len
 */
int
rs_avp_fragmented_value(rs_const_avp *vps,
		        unsigned char *buf,
		        size_t *len);

/** Copy \a len octets in \a buf to AVP \a vp */
int
rs_avp_octets_set(rs_avp *vp,
		  const unsigned char *buf,
		  size_t len);

/** Return IFID value of \a vp */
int
rs_avp_ifid_value(rs_const_avp *vp, uint8_t val[8]);

int
rs_avp_ifid_set(rs_avp *vp, const uint8_t val[8]);

/** Return byte value of \a vp */
uint8_t
rs_avp_byte_value(rs_const_avp *vp);

/** Set AVP \a vp to byte \a val */
int
rs_avp_byte_set(rs_avp *vp, uint8_t val);

/** Return short value of \a vp */
uint16_t
rs_avp_short_value(rs_const_avp *vp);

/** Set AVP \a vp to short integer \a val */
int
rs_avp_short_set(rs_avp *vp, uint16_t val);

/** Display possibly \a canonical attribute name into \a buffer */
int
rs_attr_display_name (unsigned int attr,
                      unsigned int vendor,
                      char *buffer,
                      size_t bufsize,
                      int canonical);

/** Display AVP \a vp into \a buffer */
size_t
rs_avp_display_value(rs_const_avp *vp,
                     char *buffer,
                     size_t buflen);

int
rs_attr_parse_name (const char *name,
		    unsigned int *attr,
		    unsigned int *vendor);

/** Lookup attribute \a name */
int
rs_attr_find(const char *name,
             unsigned int *attr,
             unsigned int *vendor);

/** Return dictionary name for AVP \a vp */
const char *
rs_avp_name(rs_const_avp *vp);

#if defined (__cplusplus)
}
#endif

#endif /* _RADSEC_RADSEC_H_ */

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
