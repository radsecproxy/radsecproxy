/** @file libradsec.h
    @brief Header file for libradsec.  */

/* FIXME: License blurb goes here.  */

#include <stdint.h>
#include "../list.h"		/* FIXME: ../ is not very nice */

#define RS_HEADER_LEN 4


/* Data types.  */

enum rs_conn_type {
    RS_CONN_TYPE_NONE = 0,
    RS_CONN_TYPE_UDP,
    RS_CONN_TYPE_TCP,
    RS_CONN_TYPE_TLS,
    RS_CONN_TYPE_DTLS,
};

enum rs_cred_type {
    RS_CRED_NONE = 0,
    RS_CRED_TLS_PSK_RSA,	/* RFC 4279.  */
};

struct rs_credentials {
    enum rs_cred_type type;
    char *identity;
    char *secret;
};

typedef void * (*rs_calloc)(size_t nmemb, size_t size);
typedef void * (*rs_malloc)(size_t size);
typedef void (*rs_free)(void *ptr);
typedef void * (*rs_realloc)(void *ptr, size_t size);
struct rs_alloc_scheme {
    rs_calloc calloc;
    rs_malloc malloc;
    rs_free free;
    rs_realloc realloc;
};

struct rs_config {
    enum rs_conn_type conn_type;
    struct rs_credentials transport_credentials;
    struct rs_alloc_scheme alloc_scheme;
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
