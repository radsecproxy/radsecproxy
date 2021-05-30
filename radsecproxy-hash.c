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
	  "usage: radsecproxy-hash [-h] [-k key] [mac]...\n"
#if defined(READ_CONFIG)
	  "   -c configfile\tuse configuration from CONFIGFILE\n"
#endif
	  "   -h\t\t\tdisplay this help and exit\n"
	  "   -k key\t\tuse KEY for HMAC\n"
      "      mac\t\tMAC address to hash. Read from stdin if omittedn.\n");
  exit(1);
}

#define MYNAME "radsecproxy-hash"

void
print_hash(uint8_t *mac, uint8_t *key) {
    uint8_t buf[64+1];

    if (fticks_hashmac(mac, key, sizeof(buf), buf) != 0) {
        fprintf(stderr, "%s: out of memory\n", MYNAME);
        exit(3);
    }
    puts((const char *) buf);
}

int
main(int argc, char *argv[])
{
  int opt;
#if defined(READ_CONFIG)
  char *config = NULL;
#endif
  char mac[80+1];
  uint8_t *key = NULL;

  while ((opt = getopt(argc, argv, "hk:")) != -1) {
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
    default:
      usage();
    }
  }

  if (optind < argc) {
      while (optind < argc) {
          print_hash((uint8_t *)argv[optind++], key);
      }
  } else {
      while (fgets(mac, sizeof(mac), stdin) != NULL) {
          print_hash((uint8_t *)mac, key);
      }
  }

  return 0;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
