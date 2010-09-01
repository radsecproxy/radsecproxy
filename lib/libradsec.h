/** @file libradsec.h
    @brief Header file for libradsec.  */

/* FIXME: License blurb goes here.  */

#include <stdint.h>
#include <sys/socket.h>
#include "../list.h"

/* Data types.  */

struct rs_config {
    /* FIXME: What's in here that's not in struct rs_conn or
     * rs_credentials?  */;
};

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

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
