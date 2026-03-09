/* Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include <string.h>
#include <openssl/err.h>
#include "utilcrypto.h"
#include "debug.h"

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
    if (!EVP_DigestInit_ex(ctx, digest, NULL)) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

int pwdcrypt(char encrypt_flag, uint8_t *in, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt, uint8_t saltlen) {
    EVP_MD_CTX *mdctx = mdctxcreate(md5digest());
    unsigned char hash[EVP_MD_size(md5digest())], *input;
    uint8_t i, offset = 0, out[128];
    long err = 0;

    if (!mdctx) {
        debug(DBG_ERR, "pwdcrypt: creating EVP_MD_CTX failed");
        return 0;
    }

    input = auth;
    for (;;) {
        if (!EVP_DigestInit_ex(mdctx, NULL, NULL) ||
            !EVP_DigestUpdate(mdctx, shared, sharedlen) ||
            !EVP_DigestUpdate(mdctx, input, 16))
            goto errexit;
        if (salt) {
            if (!EVP_DigestUpdate(mdctx, salt, saltlen))
                goto errexit;
            salt = NULL;
        }
        if (!EVP_DigestFinal_ex(mdctx, hash, NULL))
            goto errexit;
        for (i = 0; i < 16; i++)
            out[offset + i] = hash[i] ^ in[offset + i];
        if (encrypt_flag)
            input = out + offset;
        else
            input = in + offset;
        offset += 16;
        if (offset == len)
            break;
    }
    memcpy(in, out, len);

    EVP_MD_CTX_free(mdctx);
    return 1;

errexit:
    while ((err = ERR_get_error()))
        debug(DBG_ERR, "pwdcrypt: digest failed: %s", ERR_error_string(err, NULL));
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int pwdrecrypt(uint8_t *pwd, uint8_t len, uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len, uint8_t *oldauth, uint8_t *newauth,
               uint8_t *oldsalt, uint8_t oldsaltlen, uint8_t *newsalt, uint8_t newsaltlen) {
    if (!pwdcrypt(0, pwd, len, oldsecret, oldsecret_len, oldauth, oldsalt, oldsaltlen)) {
        debug(DBG_WARN, "pwdrecrypt: cannot decrypt password");
        return 0;
    }
#ifdef DEBUG
    printfchars(NULL, "pwdrecrypt: password", "%02x ", pwd, len);
#endif
    if (!pwdcrypt(1, pwd, len, newsecret, newsecret_len, newauth, newsalt, newsaltlen)) {
        debug(DBG_WARN, "pwdrecrypt: cannot encrypt password");
        return 0;
    }
    return 1;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
