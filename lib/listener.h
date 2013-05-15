/* Copyright 2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

/** Maximum number of pending connection requests. */
#define LISTENER_BACKLOG -1

void listener_accept_cb_(struct evconnlistener *evconnlistener,
                         evutil_socket_t fd,
                         struct sockaddr *sa,
                         int socklen,
                         void *data);
void listener_err_cb_(struct evconnlistener *listener, void *user_data);
struct rs_listener *listener_create(struct rs_context *ctx,
                                    struct rs_listener **rootp);
