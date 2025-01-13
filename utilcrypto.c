/* Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include "utilcrypto.h"

/* OpenSSL documentation mentions performance implications when using EVP_ digest functions,
 * convert to a singleton.
*/
const EVP_MD *md5digest(void) {
    static const EVP_MD *md5;
    if (!md5)
        md5 = EVP_md5();
    return md5;
}

const EVP_MD *sha256digest(void) {
    static const EVP_MD *sha256;
    if (!sha256)
        sha256 = EVP_sha256();
    return sha256;
}

EVP_MD_CTX *mdctxcreate(const EVP_MD *digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return NULL;
    if (!EVP_DigestInit(ctx, digest)) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
