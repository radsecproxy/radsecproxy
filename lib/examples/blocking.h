#include "libradsec-base.h"

struct rs_packet *next_packet (const struct rs_handle *ctx, int fd);
int send_packet (const struct rs_handle *ctx, int fd, struct rs_packet *p);
