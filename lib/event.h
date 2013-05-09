/* Copyright 2011-2012 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

void event_on_disconnect (struct rs_connection *conn);
int event_on_connect (struct rs_connection *conn, struct rs_packet *pkt);
int event_loopbreak (struct rs_connection *conn);
int event_init_eventbase (struct rs_connection *conn);
int event_init_socket (struct rs_connection *conn, struct rs_peer *p);
int event_init_bufferevent (struct rs_connection *conn, struct rs_peer *peer);
void event_do_connect (struct rs_connection *conn);
void event_conn_timeout_cb (int fd, short event, void *data);
void event_retransmit_timeout_cb (int fd, short event, void *data);
