/* RADIUS client doing blocking i/o.  */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <freeradius/libradius.h>
#include "../libradsec.h"
#include "../debug.h"

#define SECRET "sikrit"
#define USER_NAME "bob"
#define USER_PW "hemligt"

int
rsx_client ()
{
  fr_randctx fr_ctx;
  struct rs_handle *ctx;
  struct rs_connection *conn;
  RADIUS_PACKET *pkt;
  VALUE_PAIR *vp;
  char user_pw[MAX_STRING_LEN];
  uint8_t reqauth[AUTH_VECTOR_LEN];

  fr_log_fp = stderr;
  fr_debug_flag = 1;
  fr_randinit (&fr_ctx, 0);
  fr_rand_seed (NULL, 0);

  printf ("creating context\n");
  if (rs_context_create(&ctx))
    return -1;

#if 0
  printf ("reading config\n");
  if (rs_context_config_read(ctx, "libradsec.conf"))
    return -1;
#endif

  printf ("init dict");
  if (dict_init("/usr/share/freeradius", "dictionary"))
    return -1;

#if 0
  printf ("creating connection\n");
  if (rs_conn_create(ctx, &conn))
    return -1;
#endif

  printf ("creating a packet\n");
  pkt = rad_alloc (1);
  if (!pkt) {
    fr_perror ("pairmake");
    return -1;
  }

  {
    size_t pwlen =  sizeof(USER_PW);
    strncpy (user_pw, USER_PW, sizeof(user_pw));
    rad_pwencode(user_pw, &pwlen, SECRET, reqauth);
  }

  printf ("creating value pairs\n");
  vp = pairmake ("User-Name", USER_NAME, 0);
  if (!vp) {
    fr_perror ("paircreate");
    return -1;
  }
  pairadd (&vp, pairmake ("User-Password", user_pw, 0));
  pkt->vps = vp;

  printf ("attributes:\n");
  vp_printlist (stdout, vp);

  printf ("encoding packet\n");
  rad_encode (pkt, NULL, SECRET);
  print_hex (pkt);		/* DEBUG */

#if 0
  rs_packet_create (&pkt, RS_ACCESS_REQUEST);
  rs_attrib_create (&attr, RS_...);
  rs_packet_add_attrib (pkt, attr);
#endif

  //rs_packet_send (conn, pkt, ...);

  rad_free(&pkt);

#if 0
  printf ("destroying connection\n");
  if (rs_conn_destroy(conn))
    return -1;
#endif

  printf ("destroying context\n");
  rs_context_destroy(ctx);

  return 0;
}

int
main (int argc, char *argv[])
{
  exit (rsx_client ());
}
