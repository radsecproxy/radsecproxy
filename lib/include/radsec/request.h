/** \file request.h
    \brief Public interface for libradsec request's.  */

/* See LICENSE for licensing information.  */

#ifndef _RADSEC_REQUEST_H_
#define _RADSEC_REQUEST_H_ 1

/* Backwards compatible with 0.0.2. */
#define rs_request_add_reqpkt rs_request_add_reqmsg
#define rs_request_get_reqpkt rs_request_get_reqmsg

struct rs_request;

#if defined (__cplusplus)
extern "C" {
#endif

/** Create a request associated with connection \a conn.  */
int rs_request_create(struct rs_connection *conn, struct rs_request **req_out);

/** Add RADIUS request message \a req_msg to request \a req. */
void rs_request_add_reqmsg(struct rs_request *req, struct rs_message *req_msg);

/** Create a request associated with connection \a conn containing a
    newly created RADIUS authentication message, possibly with
    \a user_name and \a user_pw attributes.  \a user_name and \a user_pw
    are optional and can be NULL. If \a user_name and \a user_pw are provided,
    \a secret must also be provided. \a secret is used for "hiding" the
    password. */
int rs_request_create_authn(struct rs_connection *conn,
			    struct rs_request **req_out,
			    const char *user_name,
			    const char *user_pw,
                            const char *secret);

/** Send request \a req and wait for a matching response.  The
    response is put in \a resp_msg (if not NULL).  NOTE: At present,
    no more than one outstanding request to a given realm is
    supported.  This will change in a future version.  */
int rs_request_send(struct rs_request *req, struct rs_message **resp_msg);

/** Free all memory allocated by request \a req including any request
    message associated with the request.  Note that a request must be
    freed before its associated connection can be freed.  */
void rs_request_destroy(struct rs_request *req);

/** Return request message in request \a req.  */
struct rs_message *rs_request_get_reqmsg(const struct rs_request *req);

#if defined (__cplusplus)
}
#endif

#endif /* _RADSEC_REQUEST_H_ */
