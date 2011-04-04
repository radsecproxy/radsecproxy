/* Copyright (C) 2011 NORDUnet A/S
 * See LICENSE for information about licensing.
 */

#include <stdio.h>		/* For sprintf().  */
#include <string.h>
#include <nettle/sha.h>
#include <nettle/hmac.h>

static void
format_hash(const uint8_t *hash, size_t out_len, uint8_t *out)
{
    int i;

    for (i = 0; i < out_len / 2; i++)
	sprintf((char *) out + i*2, "%02x", hash[i % SHA256_DIGEST_SIZE]);
}

static void
hash(const uint8_t *in,
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
	format_hash(hash, out_len, out);
    }
    else {
	struct hmac_sha256_ctx ctx;
	uint8_t hash[SHA256_DIGEST_SIZE];

	hmac_sha256_set_key(&ctx, strlen((char *) key), key);
	hmac_sha256_update(&ctx, strlen((char *) in), in);
	hmac_sha256_digest(&ctx, sizeof(hash), hash);
	format_hash(hash, out_len, out);
    }
}

/** Hash the MAC in \a IN, keying with \a KEY if it's not NULL.

    \a IN and \a KEY are NULL terminated strings.

    \a IN is sanitised by lowercasing it, removing all but [0-9a-f]
    and truncating it at first ';' (due to RADIUS praxis with tacking
    on SSID to MAC in Calling-Station-Id).  */
void
fticks_hashmac(const uint8_t *in,
	       const uint8_t *key,
	       size_t out_len,
	       uint8_t *out)
{
    /* TODO: lowercase */
    /* TODO: s/[!0-9a-f]//1 */
    /* TODO: truncate after first ';', if any */

    hash(in, key, out_len, out);
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
