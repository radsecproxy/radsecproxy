/* Copyright (c) 2011,2013, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "radsecproxy.h"
#include "fticks_hashmac.h"

void
usage()
{
  fprintf(stderr,
	  "usage: radsecproxy-hash [-h] [-k key] [-t type]\n"
#if defined(READ_CONFIG)
	  "   -c configfile\tuse configuration from CONFIGFILE\n"
#endif
	  "   -h\t\t\tdisplay this help and exit\n"
	  "   -k key\t\tuse KEY for HMAC\n"
	  "   -t type\t\tprint digest of type TYPE [hash|hmac]\n");
  exit(1);
}

#define MYNAME "radsecproxy-hash"

int
main(int argc, char *argv[])
{
  int opt;
#if defined(READ_CONFIG)
  char *config = NULL;
#endif
  uint8_t buf[64+1];
  char mac[80+1];
  uint8_t *key = NULL;
  enum { TYPE_HASH, TYPE_HMAC } type = TYPE_HASH;

  while ((opt = getopt(argc, argv, "hk:t:")) != -1) {
    switch (opt) {
#if defined(READ_CONFIG)
    case 'c':
      config = optarg;
      break;
#endif
    case 'h':
      usage();
    case 'k':
      key = (uint8_t *) optarg;
      break;
    case 't':
      if (strcmp(optarg, "hash") == 0)
	type = TYPE_HASH;
      else if (strcmp(optarg, "hmac") == 0)
	type = TYPE_HMAC;
      else
	usage();
      break;
    default:
      usage();
    }
  }

  while (fgets(mac, sizeof(mac), stdin) != NULL) {
    if (type == TYPE_HASH) {
      if (fticks_hashmac((uint8_t *) mac, NULL, sizeof(buf), buf) != 0) {
	fprintf(stderr, "%s: out of memory\n", MYNAME);
	return 3;
      }
    }
    else if (type == TYPE_HMAC) {
      if (key == NULL) {
	fprintf(stderr, "%s: generating HMAC requires a key, use `-k'\n",
		MYNAME);
	return 2;
      }
      if (fticks_hashmac((uint8_t *) mac, key, sizeof(buf), buf) != 0) {
	fprintf(stderr, "%s: out of memory\n", MYNAME);
	return 3;
      }
    }
    puts((const char *) buf);
  }

  return 0;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
