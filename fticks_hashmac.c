/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <nettle/sha.h>
#include <nettle/hmac.h>
#include "fticks_hashmac.h"

static void
_format_hash(const uint8_t *hash, size_t out_len, uint8_t *out)
{
    int ir, iw;

    for (ir = 0, iw = 0; iw <= out_len - 3; ir++, iw += 2)
	sprintf((char *) out + iw, "%02x", hash[ir % SHA256_DIGEST_SIZE]);
}

static void
_hash(const uint8_t *in,
      const uint8_t *key,
      size_t out_len,
      uint8_t *out)
{
    if (key == NULL) {
	struct sha256_ctx ctx;
	uint8_t hash[SHA256_DIGEST_SIZE];

	sha256_init(&ctx);
	sha256_update(&ctx, strlen((char *) in), in);
	sha256_digest(&ctx, sizeof(hash), hash);
	_format_hash(hash, out_len, out);
    }
    else {
	struct hmac_sha256_ctx ctx;
	uint8_t hash[SHA256_DIGEST_SIZE];

	hmac_sha256_set_key(&ctx, strlen((char *) key), key);
	hmac_sha256_update(&ctx, strlen((char *) in), in);
	hmac_sha256_digest(&ctx, sizeof(hash), hash);
	_format_hash(hash, out_len, out);
    }
}

/** Hash the Ethernet MAC address in \a IN, keying a HMAC with \a KEY
    unless \a KEY is NULL.  If \a KEY is null \a IN is hashed with an
    ordinary cryptographic hash function such as SHA-2.

    \a IN and \a KEY are NULL terminated strings.

    \a IN is supposed to be an Ethernet MAC address and is sanitised
    by lowercasing it, removing all but [0-9a-f] and truncating it at
    the first ';' found.  The truncation is done because RADIUS
    supposedly has a praxis of tacking on SSID to the MAC address in
    Calling-Station-Id.

    \return 0 on success, -ENOMEM on out of memory.
*/
int
fticks_hashmac(const uint8_t *in,
	       const uint8_t *key,
	       size_t out_len,
	       uint8_t *out)
{
    uint8_t *in_copy = NULL;
    uint8_t *p = NULL;
    int i;

    in_copy = calloc(1, strlen((const char *) in) + 1);
    if (in_copy == NULL)
	return -ENOMEM;

    /* Sanitise and lowercase 'in' into 'in_copy'.  */
    for (i = 0, p = in_copy; in[i] != '\0'; i++) {
	if (in[i] == ';') {
	    *p++ = '\0';
	    break;
	}
	if (in[i] >= '0' && in[i] <= '9') {
	    *p++ = in[i];
	}
	else if (tolower(in[i]) >= 'a' && tolower(in[i]) <= 'f') {
	    *p++ = tolower(in[i]);
	}
    }

    _hash(in_copy, key, out_len, out);
    free(in_copy);
    return 0;
}
