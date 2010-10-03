/* See the file COPYING for licensing information.  */

struct rs_request;

int rs_req_create(struct rs_connection *conn, struct rs_request **req_out);
void rs_req_destroy(struct rs_request *request);
int rs_req_send(struct rs_request *request, struct rs_packet *req, struct rs_packet **resp);
