/*! \file libradsec.h
  \brief Header file for libradsec.  */

/* FIXME: License blurb goes here.  */

#include <stdint.h>
#include <sys/socket.h>
#include "../list.h"


/* Data types.  */

enum rs_cred_type {
    RS_CRED_NONE = 0,
    RS_CRED_TLS_PSK_RSA,	/* RFC 4279.  */
};

struct rs_credentials {
    enum rs_cred_type type;
    char *identity;
    char *secret;		/* Passphrase or PSK.  */
};

enum rs_conn_type {
    RS_CONN_TYPE_NONE = 0,
    RS_CONN_TYPE_UDP,
    RS_CONN_TYPE_TCP,
    RS_CONN_TYPE_TLS,
    RS_CONN_TYPE_DTLS,
};
struct rs_conn {
    enum rs_conn_type type;
    struct rs_credentials transport_credentials;
    struct sockaddr_storage addr;
    char open_flag;
};

struct rs_attribute {
    uint8_t type;
    uint8_t lenght;
    uint8_t *value;
};

struct rs_packet {
    uint8_t code;
    uint8_t id;
    uint8_t auth[16];
    struct list *attrs;
};


typedef void (*rs_conn_connected_cb)(void *user_data /* FIXME: peer? */);
typedef void (*rs_conn_disconnected_cb)(void *user_data /* FIXME: reason? */);
typedef void (*rs_conn_packet_received_cb)(const struct rs_packet *packet,
					   void *user_data);
typedef void (*rs_conn_packet_sent_cb)(void *user_data);

/*! Connection callbacks.  */
struct rs_conn_callbacks {
    /*! Callback invoked when the connection has been established.  */
    rs_conn_connected_cb connected_cb;
    /*! Callback invoked when the connection has been torn down.  */
    rs_conn_disconnected_cb disconnected_cb;
    /*! Callback invoked when a packet was received.  */
    rs_conn_packet_received_cb received_cb;
    /*! Callback invoked when a packet was successfully sent.  */
    rs_conn_packet_sent_cb sent_cb;
};


/* Function prototypes.  */

/*
  FIXME: Do we want alloc and free?  Or perhaps init and free,
  decoupling allocation from initialization?  IMO we want _some_ init
  function, f.ex. for setting open_flag = 1 when type == UDP.

struct conn *conn_alloc (enum conn_type type, struct sockaddr_in6 address, ...);
void conn_free (struct conn *conn);
*/

/*! Open connection and return 0 on success.
    \param conn Connection object, obtained through a call to \a
    conn_alloc.
    \param cb Callbacks for events on the connection.  If NULL, all I/O
    will be blocking.
    \param user_data A pointer passed to the callbacks when invoked.  */
int rs_conn_open(struct rs_conn *conn,
		 const struct rs_conn_callbacks *cb,
		 void *user_data);

/*! Close connection and return 0 on success.
    \param conn Connection object, obtained through a call to \a
    conn_alloc.
    \param user_data A pointer passed to the callbacks when the \a
    disconnected_cb in \a conn is invoked.  */
int rs_conn_close(struct rs_conn *conn, void *user_data); /* FIXME: return type?  */

/*! Allocate a packet object.  Should be freed using \a rs_packet_free.  */
struct rs_packet *rs_packet_alloc();

/*! Free a packet object previously allocated with \a rs_packet_alloc.  */
void rs_packet_free();

/*! Add an attribute to a packet.
    \param packet The packet.
    \param attribute Attribute to add to packet.  */
int rs_packet_add_attribute(struct rs_packet *packet,
			    const struct rs_attribute *attribute);

/*! Send \a packet on \a conn and return 0 on success.
    \param conn Connection object, obtained through a call to \a
    conn_alloc and opened with \a rs_conn_open.
    \param packet Packet to send.
    \param user_data Pointer passed to \a rs_conn_packet_sent_cb, invoked
    when packet has been sent.
 */
int rs_packet_send(const struct rs_conn *conn,
		   const struct rs_packet *packet,
		   void *user_data);

/*! Return the next packet received on \a conn, blocking while waiting.
  The packet returned must be freed using \a rs_packet_free.  */
struct rs_packet *rs_packet_receive(const struct rs_conn *conn);


/* Thinking out loud here...

   We could let the user drive the underlying libevent event loop in
   three different ways, from easiest to hairiest:

   i) Blocking i/o model: User passes NULL for the callbacks in
   rc_conn_open() and the open, send and receive calls will block
   until the wanted event occurs.  Other events occurring while
   waiting will be either silently discarded or signaled as an error
   (f.ex. broken connection while sending).

   ii) Simple interface with a timeout: User calls
   rs_event_loop(timeout) to process pending i/o.

   iii) full libevent interface: TODO.
 */
#error "need an rs_event_loop() and more"


/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
