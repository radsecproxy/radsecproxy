/* Copyright (c) 2011,2013, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include "fticks_hashmac.h"
#include "utilcrypto.h"
#include <ctype.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** \a HASH is an input buffer of length SHA256_DIGEST_SIZE bytes.
    \a OUT_LEN is the size in bytes of \OUT.
    \a OUT is an output buffer of length \a OUT_LEN. */
static void _format_hash(const uint8_t *hash, size_t out_len, uint8_t *out) {
    int ir, iw;

    if (out_len < 3) {
        memset(out, 0, out_len);
        return;
    }

    for (ir = 0, iw = 0; iw <= out_len - 3; ir++, iw += 2)
        sprintf((char *)out + iw, "%02x", hash[ir % EVP_MD_size(sha256digest())]);
}

static void _hash(const uint8_t *in,
                  const uint8_t *key,
                  size_t out_len,
                  uint8_t *out) {
    uint8_t hash[EVP_MD_size(sha256digest())];
    if (out_len > 0)
        out[0] = '\0';

    if (key == NULL) {
        EVP_MD_CTX *ctx = mdctxcreate(sha256digest());
        if (!ctx)
            return;

        EVP_DigestUpdate(ctx, in, strlen((char *)in));
        EVP_DigestFinal(ctx, hash, NULL);
        _format_hash(hash, out_len, out);
        EVP_MD_CTX_free(ctx);
    } else {
        if (!HMAC(sha256digest(), key, strlen((char *)key), in, strlen((char *)in), hash, NULL))
            return;
        _format_hash(hash, out_len, out);
    }
}

/** Hash the Ethernet MAC address in \a IN, keying a HMAC with \a KEY
    unless \a KEY is NULL.  If \a KEY is null \a IN is hashed with an
    ordinary cryptographic hash function such as SHA-2.

    \a IN and \a KEY are NUL terminated strings.

    \a IN is supposed to be an Ethernet MAC address and is sanitised
    by lowercasing it, removing all but [0-9a-f] and truncating it at
    the first ';' found.  The truncation is done because RADIUS
    supposedly has a praxis of tacking on SSID to the MAC address in
    Calling-Station-Id.

    The resulting hash value is written to \a OUT as a NUL terminated
    string of numbers in two-digit hexadecimal ASCII representation.

    Exactly \a OUT_LEN bytes are written to \a OUT, based on the first
    (\a OUT_LEN - 1) / 2 bytes of the hash. Note that in the case when
    \OUT_LEN - 1 is more than two times the length of the hash, the
    output is repeated by concatinating another hex ASCII
    representation of the hash to the output until the buffer is full.

    \return 0 on success, -ENOMEM on out of memory.
*/
int fticks_hashmac(const uint8_t *in,
                   const uint8_t *key,
                   size_t out_len,
                   uint8_t *out) {
    uint8_t *in_copy = NULL;
    uint8_t *p = NULL;
    int i;

    in_copy = calloc(1, strlen((const char *)in) + 1);
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
        } else if (tolower(in[i]) >= 'a' && tolower(in[i]) <= 'f') {
            *p++ = tolower(in[i]);
        }
    }

    _hash(in_copy, key, out_len, out);
    free(in_copy);
    return 0;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
