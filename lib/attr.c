#include <freeradius/libradius.h>
#include "libradsec.h"
#include "libradsec-impl.h"

fixme
attr_create(fixme)
{

  printf ("creating value pairs\n");
  /* User-Name.  */
  vp = pairmake ("User-Name", USER_NAME, 0);
  if (!vp) {
    fr_perror ("pairmake");
    return -1;
  }

  /* User-Password.  */
  {
    size_t pwlen =  sizeof(USER_PW);
    strncpy (user_pw, USER_PW, sizeof(user_pw));
    rad_pwencode(user_pw, &pwlen, SECRET, reqauth);
  }
  pairadd (&vp, pairmake ("User-Password", user_pw, 0));
  pkt->vps = vp;

  printf ("attributes:\n");
  vp_printlist (stdout, vp);
}
