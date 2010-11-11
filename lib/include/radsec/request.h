/* See the file COPYING for licensing information.  */

struct rs_request;

#if defined (__cplusplus)
extern "C" {
#endif

int rs_request_create(struct rs_connection *conn, struct rs_request **req_out);
void rs_request_destroy(struct rs_request *request);
int rs_request_send(struct rs_request *request, struct rs_packet *req, struct rs_packet **resp);

#if defined (__cplusplus)
}
#endif
