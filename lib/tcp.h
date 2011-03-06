/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

void tcp_event_cb (struct bufferevent *bev, short events, void *user_data);
void tcp_read_cb (struct bufferevent *bev, void *user_data);
void tcp_write_cb (struct bufferevent *bev, void *ctx);
