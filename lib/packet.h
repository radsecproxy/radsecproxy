/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

int packet_do_send (struct rs_packet *pkt);
int packet_verify_response (struct rs_connection *conn,
			    struct rs_packet *response,
			    struct rs_packet *request);
