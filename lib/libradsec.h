/** @file libradsec.h
    @brief Header file for libradsec.  */

/* FIXME: License blurb goes here.  */

#include <unistd.h>
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
typedef unsigned int rs_conn_type_t;

enum rs_cred_type {
    RS_CRED_NONE = 0,
    RS_CRED_TLS_PSK_RSA,	/* RFC 4279.  */
};
typedef unsigned int rs_cred_type_t;

struct rs_credentials {
    enum rs_cred_type type;
    char *identity;
    char *secret;
};

typedef void * (*rs_calloc_fp)(size_t nmemb, size_t size);
typedef void * (*rs_malloc_fp)(size_t size);
typedef void (*rs_free_fp)(void *ptr);
typedef void * (*rs_realloc_fp)(void *ptr, size_t size);
struct rs_alloc_scheme {
    rs_calloc_fp calloc;
    rs_malloc_fp malloc;
    rs_free_fp free;
    rs_realloc_fp realloc;
};

struct rs_config {
    enum rs_conn_type conn_type;
    struct rs_credentials transport_credentials;
    struct rs_alloc_scheme alloc_scheme;
};

struct rs_attribute {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
};

struct rs_packet {
    uint8_t code;
    uint8_t id;
    uint8_t auth[16];
    struct list *attrs;
};


/* Convenience macros.  */
#define rs_calloc(ctx, nmemb, size) \
    (ctx->alloc_scheme.calloc ? ctx->alloc_scheme.calloc : calloc)(nmemb, size)
#define rs_malloc(ctx, size) \
    (ctx->alloc_scheme.malloc ? ctx->alloc_scheme.malloc : malloc)(size)
#define rs_free(ctx, ptr) \
    (ctx->alloc_scheme.free ? ctx->alloc_scheme.free : free)(ptr)
#define rs_(ctx, realloc, ptr, size) \
    (ctx->alloc_scheme.realloc ? ctx->alloc_scheme.realloc : realloc)(ptr, size)

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
