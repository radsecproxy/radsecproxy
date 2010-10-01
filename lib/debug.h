/* See the file COPYING for licensing information.  */

#define hd(p, l) { int i;		\
    for (i = 1; i <= l; i++) {		\
      printf ("%02x ", p[i-1]);		\
      if (i % 8 == 0) printf (" ");	\
      if (i % 16 == 0) printf ("\n"); }	\
    printf ("\n"); }

void rs_dump_packet (const struct rs_packet *pkt);
void rs_dump_attr (const struct rs_attr *attr);
