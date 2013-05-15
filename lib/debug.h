/* Copyright 2011 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#define hd(p, l) { int i;		\
    for (i = 1; i <= l; i++) {		\
      printf ("%02x ", p[i-1]);		\
      if (i % 8 == 0) printf (" ");	\
      if (i % 16 == 0) printf ("\n"); }	\
    printf ("\n"); }

#if defined (__cplusplus)
extern "C" {
#endif

struct rs_message;
void rs_dump_message (const struct rs_message *pkt);
int _rs_debug (const char *fmt, ...);

#if defined (DEBUG)
#define rs_debug(x) _rs_debug x
#else
#define rs_debug(x) do {;} while (0)
#endif

#if defined (__cplusplus)
}
#endif
