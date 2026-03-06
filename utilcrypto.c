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

int msmppencrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    EVP_MD_CTX *mdctx = mdctxcreate(md5digest());
    unsigned char hash[EVP_MD_size(md5digest())];
    uint8_t i, offset;
    long err = 0;

    if (!mdctx) {
        debug(DBG_ERR, "msmppencrypt: creating EVP_MD_CTX failed");
        return 0;
    }

#if 0
    printfchars(NULL, "msppencrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppencrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppencrypt in", "%02x ", text, len);
#endif

    if (!EVP_DigestUpdate(mdctx, shared, sharedlen) ||
        !EVP_DigestUpdate(mdctx, auth, 16) ||
        !EVP_DigestUpdate(mdctx, salt, 2) ||
        !EVP_DigestFinal_ex(mdctx, hash, NULL))
        goto errexit;

#if 0
    printfchars(NULL, "msppencrypt hash", "%02x ", hash, 16);
#endif

    for (i = 0; i < 16; i++)
        text[i] ^= hash[i];

    for (offset = 16; offset < len; offset += 16) {
#if 0
	printf("text + offset - 16 c(%d): ", offset / 16);
	printfchars(NULL, NULL, "%02x ", text + offset - 16, 16);
#endif
        if (!EVP_DigestInit_ex(mdctx, NULL, NULL) ||
            !EVP_DigestUpdate(mdctx, shared, sharedlen) ||
            !EVP_DigestUpdate(mdctx, text + offset - 16, 16) ||
            !EVP_DigestFinal_ex(mdctx, hash, NULL))
            goto errexit;
#if 0
	printfchars(NULL, "msppencrypt hash", "%02x ", hash, 16);
#endif

        for (i = 0; i < 16; i++)
            text[offset + i] ^= hash[i];
    }

#if 0
    printfchars(NULL, "msppencrypt out", "%02x ", text, len);
#endif

    EVP_MD_CTX_free(mdctx);
    return 1;

errexit:
    while ((err = ERR_get_error()))
        debug(DBG_ERR, "msmppencrypt: digest failed: %s", ERR_error_string(err, NULL));
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int msmppdecrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    EVP_MD_CTX *mdctx = mdctxcreate(md5digest());
    unsigned char hash[EVP_MD_size(md5digest())];
    uint8_t i, offset;
    char plain[255];
    long err = 0;

    if (!mdctx) {
        debug(DBG_ERR, "msmppdecrypt: creating EVP_MD_CTX failed");
        return 0;
    }

#if 0
    printfchars(NULL, "msppdecrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppdecrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppdecrypt in", "%02x ", text, len);
#endif

    if (!EVP_DigestUpdate(mdctx, shared, sharedlen) ||
        !EVP_DigestUpdate(mdctx, auth, 16) ||
        !EVP_DigestUpdate(mdctx, salt, 2) ||
        !EVP_DigestFinal_ex(mdctx, hash, NULL))
        goto errexit;

#if 0
    printfchars(NULL, "msppdecrypt hash", "%02x ", hash, 16);
#endif

    for (i = 0; i < 16; i++)
        plain[i] = text[i] ^ hash[i];

    for (offset = 16; offset < len; offset += 16) {
#if 0
	printf("text + offset - 16 c(%d): ", offset / 16);
	printfchars(NULL, NULL, "%02x ", text + offset - 16, 16);
#endif
        if (!EVP_DigestInit_ex(mdctx, NULL, NULL) ||
            !EVP_DigestUpdate(mdctx, shared, sharedlen) ||
            !EVP_DigestUpdate(mdctx, text + offset - 16, 16) ||
            !EVP_DigestFinal(mdctx, hash, NULL))
            goto errexit;
#if 0
	printfchars(NULL, "msppdecrypt hash", "%02x ", hash, 16);
#endif

        for (i = 0; i < 16; i++)
            plain[offset + i] = text[offset + i] ^ hash[i];
    }

    memcpy(text, plain, len);
#if 0
    printfchars(NULL, "msppdecrypt out", "%02x ", text, len);
#endif

    EVP_MD_CTX_free(mdctx);
    return 1;

errexit:
    while ((err = ERR_get_error()))
        debug(DBG_ERR, "msmppdecrypt: digest failed: %s", ERR_error_string(err, NULL));
    EVP_MD_CTX_free(mdctx);
    return 0;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
