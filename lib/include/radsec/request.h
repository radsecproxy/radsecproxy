/* See the file COPYING for licensing information.  */

struct rs_request;

#if defined (__cplusplus)
extern "C" {
#endif

int rs_request_create(struct rs_connection *conn, struct rs_request **req_out);
int rs_request_send(struct rs_request *request, struct rs_packet *req_msg, struct rs_packet **resp_msg);
void rs_request_destroy(struct rs_request *request);

#if defined (__cplusplus)
}
#endif
