/* Copyright (C) 2011 NORDUnet A/S
 * See LICENSE for information about licensing.
 */

#include <stdio.h>
#include <errno.h>
#include "../radsecproxy.h"
#include "../fticks_hashmac.h"

static int
_check_hash(const char *mac, const char *key, const char *hash, const char*hmac)
{
  int rv = 0;
  uint8_t buf[128];

  if (fticks_hashmac((const uint8_t *) mac, NULL, sizeof(buf), buf) != 0)
    return -ENOMEM;
  if (strcmp(hash, (const char *) buf) != 0)
    rv = !!fprintf(stderr, "%s: bad hash: %s\n", mac, buf);
  if (fticks_hashmac((const uint8_t *) mac, (const uint8_t *) key,
		     sizeof(buf), buf) != 0)
    return -ENOMEM;
  if (strcmp(hmac, (const char *) buf) != 0)
    rv = !!fprintf(stderr, "%s: bad hash (key=\"%s\"): %s\n", mac, key, buf);

  return rv;
}

#define MAC1 "00:23:14:0a:f7:24"
#define MAC1_UC "00:23:14:0A:F7:24"
#define MAC1_APPENDED "00:23:14:0a:f7:24;cruft"
#define MAC1_WEIRD "00:23:-[?xyzzy!]-14:0a:f7:24"
#define KEY1 "magic passphrase"
#define HASH1 "29c0ee9d9c41771795a11ff75fefe9f5ccaab523ad31fc4fd8e776c707ad158129c0ee9d9c41771795a11ff75fefe9f5ccaab523ad31fc4fd8e776c707ad15"
#define HMAC1 "57c8cd8031142c51ac9747370f48a5aa731006729d0cdf589ba101864f35f39057c8cd8031142c51ac9747370f48a5aa731006729d0cdf589ba101864f35f3"

int
main (int argc, char *argv[])
{
  if (_check_hash(MAC1, KEY1, HASH1, HMAC1) != 0)
    return 1;
  /* Again, for good measure.  (Or rather to make sure there's no
     state left.)  */
  if (_check_hash(MAC1, KEY1, HASH1, HMAC1) != 0)
    return 1;
  if (_check_hash(MAC1_UC, KEY1, HASH1, HMAC1) != 0)
    return 1;
  if (_check_hash(MAC1_APPENDED, KEY1, HASH1, HMAC1) != 0)
    return 1;
  if (_check_hash(MAC1_WEIRD, KEY1, HASH1, HMAC1) != 0)
    return 1;

  return 0;
}
