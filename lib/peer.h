/* Copyright 2011,2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

struct rs_peer *peer_create (struct rs_context *ctx, struct rs_peer **rootp);
struct rs_peer *peer_pick_peer (struct rs_connection *conn);
int peer_create_for_connbase (struct rs_conn_base *, struct rs_peer **);
