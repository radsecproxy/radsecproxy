/** \file request.h
    \brief Public interface for libradsec request's.  */

/* Copyright 2010-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#ifndef _RADSEC_REQUEST_H_
#define _RADSEC_REQUEST_H_ 1

struct rs_request;

#if defined (__cplusplus)
extern "C" {
#endif

/** Create a request associated with connection \a conn.  */
int rs_request_create(struct rs_connection *conn, struct rs_request **req_out);

/** Add RADIUS request message \a req_msg to request \a req.
    FIXME: Rename to rs_request_add_reqmsg?  */
void rs_request_add_reqpkt(struct rs_request *req, struct rs_packet *req_msg);

/** Create a request associated with connection \a conn containing a
    newly created RADIUS authentication message, possibly with \a
    user_name and \a user_pw attributes.  \a user_name and _user_pw
    are optional and can be NULL.  */
int rs_request_create_authn(struct rs_connection *conn,
			    struct rs_request **req_out,
			    const char *user_name,
			    const char *user_pw);

/** Send request \a req and wait for a matching response.  The
    response is put in \a resp_msg (if not NULL).  NOTE: At present,
    no more than one outstanding request to a given realm is
    supported.  This will change in a future version.  */
int rs_request_send(struct rs_request *req, struct rs_packet **resp_msg);

/** Free all memory allocated by request \a req including any request
    packet associated with the request.  Note that a request must be
    freed before its associated connection can be freed.  */
void rs_request_destroy(struct rs_request *req);

/** Return request message in request \a req.  */
struct rs_packet *rs_request_get_reqmsg(const struct rs_request *req);

#if defined (__cplusplus)
}
#endif

#endif /* _RADSEC_REQUEST_H_ */
