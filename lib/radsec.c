#include <stdlib.h>
#include <stdint.h>
#include "libradsec.h"
#include "libradsec-impl.h"

#define ERR_OK 0
#define ERR_NOMEM 1
#define ERR_NOSYS 2
#define ERR_SOME_ERROR 99

int rs_context_create(struct rs_handle **ctx)
{
  *ctx = (struct rs_handle *) malloc (sizeof (struct rs_handle));
  return (ctx ? ERR_OK : ERR_NOMEM);
}

void rs_context_destroy(struct rs_handle *ctx)
{
  free (ctx);
}

int rs_context_set_alloc_scheme(struct rs_handle *ctx, struct rs_alloc_scheme *scheme)
{
  return ERR_NOSYS;
}

int rs_context_config_read(struct rs_handle *ctx, const char *config_file)
{
  return ERR_NOSYS;
}

int rs_conn_create(const struct rs_handle *ctx, struct rs_connection **conn)
{
  return ERR_NOSYS;
}

int rs_conn_destroy(struct rs_connection  *conn)
{
  return ERR_NOSYS;
}

int rs_conn_set_eventbase(struct rs_connection *conn, struct event_base *eb)
{
  return ERR_NOSYS;
}

int rs_conn_set_callbacks(struct rs_connection *conn, struct rs_conn_callbacks *cb)
{
  return ERR_NOSYS;
}

int rs_conn_set_server(struct rs_connection *conn, const char *name)
{
  return ERR_NOSYS;
}

int rs_conn_get_server(const struct rs_connection *conn, const char *name, size_t buflen)
{
  return ERR_NOSYS;
}

int rs_packet_send(const struct rs_conn *conn, const struct rs_packet *pkt, void *user_data)
{
  return ERR_NOSYS;
}

int rs_packet_receive(const struct rs_conn *conn, struct rs_packet **pkt)
{
  return ERR_NOSYS;
}

