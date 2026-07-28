/* Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include <arpa/inet.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "radmsgcrypto.h"
#include "debug.h"
#include "radmsg.h"

/* OpenSSL documentation mentions performance implications when using EVP_ digest functions,
 * convert to a singleton.
*/
const EVP_MD *md5digest(void) {
    static const EVP_MD *md5;
    if (!md5)
        md5 = EVP_md5();
    return md5;
}

static EVP_MD_CTX *mdctxcreate(const EVP_MD *digest) {
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

    if (len % RAD_PWD_BLOCK_SIZE) {
        debug(DBG_ERR, "pwdcrypt: length not a multiple of 16! there is likely a bug!");
        return 0;
    }

    if (!mdctx) {
        debug(DBG_ERR, "pwdcrypt: creating EVP_MD_CTX failed");
        return 0;
    }

    input = auth;
    for (;;) {
        if (!EVP_DigestInit_ex(mdctx, NULL, NULL) ||
            !EVP_DigestUpdate(mdctx, shared, sharedlen) ||
            !EVP_DigestUpdate(mdctx, input, RAD_PWD_BLOCK_SIZE))
            goto errexit;
        if (salt) {
            if (!EVP_DigestUpdate(mdctx, salt, saltlen))
                goto errexit;
            salt = NULL;
        }
        if (!EVP_DigestFinal_ex(mdctx, hash, NULL))
            goto errexit;
        for (i = 0; i < RAD_PWD_BLOCK_SIZE; i++)
            out[offset + i] = hash[i] ^ in[offset + i];
        if (encrypt_flag)
            input = out + offset;
        else
            input = in + offset;
        offset += RAD_PWD_BLOCK_SIZE;
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

static int gensalt(unsigned char *salt, int len, uint32_t index) {
    if (!RAND_bytes(salt, len))
        return 0;
    salt[0] = (salt[0] & 0x0f) | (index << 4) | 0x80;
    return 1;
}

int _recryptattr(struct tlv *attr, uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len, uint8_t *oldauth, uint8_t *newauth) {
    uint8_t newsalt[2], saltindex = 0;
    uint8_t sublen, *subattrs;

    /* user password RFC2865 */
    if (attr->t == RAD_Attr_User_Password) {
        debug(DBG_DBG, "recryptattrs: reencrypting user password");
        if (attr->l < RAD_PWD_BLOCK_SIZE || attr->l > 128 || attr->l % RAD_PWD_BLOCK_SIZE) {
            debug(DBG_WARN, "recryptattrs: invalid user password length %d", attr->l);
            return 0;
        }
        if (!pwdrecrypt(attr->v, attr->l, oldsecret, oldsecret_len, newsecret, newsecret_len, oldauth, newauth, NULL, 0, NULL, 0))
            return 0;
    }

    /* tunnel-password RFC2868 */
    if (attr->t == RAD_Attr_Tunnel_Password) {
        debug(DBG_DBG, "recryptattrs: reencrypting tunnel password");
        if ((attr->l - RAD_PWD_SALT_LEN - 1) < RAD_PWD_BLOCK_SIZE || (attr->l - RAD_PWD_SALT_LEN - 1) % RAD_PWD_BLOCK_SIZE) {
            debug(DBG_WARN, "recryptattrs: invalid tunnel password length %d", attr->l);
            return 0;
        }
        if (!gensalt(newsalt, RAD_PWD_SALT_LEN, saltindex++))
            return 0;
        if (!pwdrecrypt(attr->v + RAD_PWD_SALT_LEN + 1, attr->l - RAD_PWD_SALT_LEN - 1, oldsecret, oldsecret_len, newsecret, newsecret_len,
                        oldauth, newauth, attr->v + 1, RAD_PWD_SALT_LEN, newsalt, RAD_PWD_SALT_LEN))
            return 0;
        memcpy(attr->v + 1, newsalt, RAD_PWD_SALT_LEN);
    }

    /* MS MPPE RFC 2548 */
    if (attr->t == RAD_Attr_Vendor_Specific) {
        if (attr->l < VSATTRMINVALLEN)
            return 1;
        if (memcmp(attr->v, RAD_VS_VENDOR_MS, VSATTRVENDORLEN) != 0)
            return 1;
        sublen = attr->l - VSATTRVENDORLEN;
        subattrs = VSATTRVAL(attr->v);
        if (!attrvalidate(subattrs, sublen)) {
            debug(DBG_WARN, "recryptattrs: invalid MS vendor specific attribute");
            return 0;
        }
        while (sublen > 1) {
            if (ATTRTYPE(subattrs) == RAD_VS_ATTR_MS_MPPE_Send_Key ||
                ATTRTYPE(subattrs) == RAD_VS_ATTR_MS_MPPE_Recv_Key) {
                debug(DBG_DBG, "recryptattrs: reencrypting msmppe key type %d", ATTRTYPE(subattrs));
                if (ATTRVALLEN(subattrs) - RAD_PWD_SALT_LEN < RAD_PWD_BLOCK_SIZE || (ATTRVALLEN(subattrs) - RAD_PWD_SALT_LEN) % RAD_PWD_BLOCK_SIZE) {
                    debug(DBG_WARN, "recryptattrs: invalid msmpp key length %d", ATTRVALLEN(subattrs));
                    return 0;
                }
                if (!gensalt(newsalt, RAD_PWD_SALT_LEN, saltindex++))
                    return 0;
                if (!pwdrecrypt(ATTRVAL(subattrs) + RAD_PWD_SALT_LEN, ATTRVALLEN(subattrs) - RAD_PWD_SALT_LEN, oldsecret, oldsecret_len, newsecret, newsecret_len,
                                oldauth, newauth, ATTRVAL(subattrs), RAD_PWD_SALT_LEN, newsalt, RAD_PWD_SALT_LEN)) {
                    debug(DBG_WARN, "recryptattrs: recrypt failed");
                    return 0;
                }
                memcpy(ATTRVAL(subattrs), newsalt, RAD_PWD_SALT_LEN);
            }
            sublen -= ATTRLEN(subattrs);
            subattrs += ATTRLEN(subattrs);
        }
    }
    return 1;
}

int recryptattrs(struct list *attrs, uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len, uint8_t *oldauth, uint8_t *newauth) {
    struct list_node *node;
    struct tlv *attr;

    for (node = list_first(attrs); node; node = list_next(node)) {
        attr = (struct tlv *)node->data;
        if (!_recryptattr(attr, oldsecret, oldsecret_len, newsecret, newsecret_len, oldauth, newauth))
            return 0;
    }

    return 1;
}

int radmsgsign(uint8_t *buf, size_t len, unsigned char *secret, size_t secret_len, uint8_t *pmsgauth, uint8_t *rqauth) {
    int skip_auth_calc = 0;

    switch (RADCODE(buf)) {
    case RAD_Accounting_Request:
    case RAD_CoA_Request:
    case RAD_Disconnect_Request:
        memset(RADAUTH(buf), 0, RADAUTHLEN);
        break;
    case RAD_Access_Accept:
    case RAD_Access_Challenge:
    case RAD_Access_Reject:
    case RAD_Accounting_Response:
    case RAD_CoA_NAK:
    case RAD_Disconnect_NAK:
        if (!rqauth) {
            debug(DBG_ERR, "radmsgsign: missing original request to sign response");
            return 0;
        }
        memcpy(RADAUTH(buf), rqauth, RADAUTHLEN);
        break;
    default:
        /* take authenticator as-is */
        skip_auth_calc = 1;
        break;
    }

    if (pmsgauth && !HMAC(md5digest(), secret, secret_len, buf, len, pmsgauth, NULL)) {
        debug(DBG_ERR, "radmsgsign: calculating HMAC failed");
        return 0;
    }

    if (!skip_auth_calc) {
        EVP_MD_CTX *mdctx = mdctxcreate(md5digest());

        if (!mdctx ||
            !EVP_DigestUpdate(mdctx, buf, len) ||
            !EVP_DigestUpdate(mdctx, secret, secret_len) ||
            !EVP_DigestFinal_ex(mdctx, RADAUTH(buf), NULL)) {
            debug(DBG_ERR, "radmsgsign: calculating MD5 hash failed");
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
        EVP_MD_CTX_free(mdctx);
    }
    return 1;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
