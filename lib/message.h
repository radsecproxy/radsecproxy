/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

int message_do_send (struct rs_message *msg);
int message_verify_response (struct rs_connection *conn,
                             struct rs_message *response,
                             struct rs_message *request);
