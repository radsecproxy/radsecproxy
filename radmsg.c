/* Copyright (c) 2007-2009, UNINETT AS */
/* See LICENSE for licensing information. */

#ifdef SYS_SOLARIS9
#include <sys/inttypes.h>
#else
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "list.h"
#include "tlv11.h"
#include "radmsg.h"
#include "debug.h"
#include <pthread.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define RADLEN(x) ntohs(((uint16_t *)(x))[1])

void radmsg_free(struct radmsg *msg) {
    if (msg) {
        freetlvlist(msg->attrs);
        free(msg);
    }
}

struct radmsg *radmsg_init(uint8_t code, uint8_t id, uint8_t *auth) {
    struct radmsg *msg;

    msg = malloc(sizeof(struct radmsg));
    if (!msg)
        return NULL;
    memset(msg, 0, sizeof(struct radmsg));
    msg->attrs = list_create();
    if (!msg->attrs) {
	free(msg);
        return NULL;
    }
    msg->code = code;
    msg->id = id;
    if (auth)
	memcpy(msg->auth, auth, 16);
    else if (!RAND_bytes(msg->auth, 16)) {
	free(msg);
	return NULL;
    }
    return msg;
}

int radmsg_add(struct radmsg *msg, struct tlv *attr) {
    if (!msg || !msg->attrs)
        return 1;
    if (!attr)
        return 0;
    return list_push(msg->attrs, attr);
}

/** Return a new list with all tlv's in \a msg of type \a type. The
 * caller is responsible for freeing the list by calling \a
 * list_free(). */
struct list *
radmsg_getalltype(const struct radmsg *msg, uint8_t type)
{
    struct list *list = NULL;
    struct list_node *node = NULL;

    if (!msg || !msg->attrs)
        return NULL;
    list = list_create();
    if (!list)
        return NULL;

    for (node = list_first(msg->attrs); node; node = list_next(node))
        if (((struct tlv *) node->data)->t == type)
            if (list_push(list, node->data) != 1) {
                list_free(list);
                return NULL;
            }
    return list;
}

/* returns first tlv of the given type */
struct tlv *radmsg_gettype(struct radmsg *msg, uint8_t type) {
    struct list_node *node;
    struct tlv *tlv;

    if (!msg)
        return NULL;
    for (node = list_first(msg->attrs); node; node = list_next(node)) {
        tlv = (struct tlv *)node->data;
        if (tlv->t == type)
            return tlv;
    }
    return NULL;
}

/** Copy all attributes of type \a type from \a src to \a dst.
 *
 * If all attributes were copied successfully, the number of
 * attributes copied is returned.
 *
 * If copying failed, a negative number is returned. */
int radmsg_copy_attrs(struct radmsg *dst,
                      const struct radmsg *src,
                      uint8_t type)
{
    struct list_node *node = NULL;
    struct list *list = radmsg_getalltype(src, type);
    int n = 0;

    for (node = list_first(list); node; node = list_next(node)) {
        if (radmsg_add(dst, copytlv((struct tlv *) node->data)) != 1) {
            n = -1;
            break;
        }
        n++;
    }
    list_free(list);
    return n;
}

int _checkmsgauth(unsigned char *rad, uint8_t *authattr, uint8_t *secret) {
    int result = 0;             /* Fail. */
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    HMAC_CTX *hmacctx = NULL;
    unsigned int md_len;
    uint8_t auth[16], hash[EVP_MAX_MD_SIZE];

    pthread_mutex_lock(&lock);

    memcpy(auth, authattr, 16);
    memset(authattr, 0, 16);
    md_len = 0;
    hmacctx = HMAC_CTX_new();
    if (!hmacctx)
        debugx(1, DBG_ERR, "%s: malloc failed", __func__);
    HMAC_Init_ex(hmacctx, secret, strlen((char *)secret), EVP_md5(), NULL);
    HMAC_Update(hmacctx, rad, RADLEN(rad));
    HMAC_Final(hmacctx, hash, &md_len);
    memcpy(authattr, auth, 16);
    if (md_len != 16) {
	debug(DBG_WARN, "message auth computation failed");
        goto out;
    }

    if (memcmp(auth, hash, 16)) {
	debug(DBG_WARN, "message authenticator, wrong value");
        goto out;
    }

    result = 1;
out:
    HMAC_CTX_free(hmacctx);
    pthread_mutex_unlock(&lock);
    return result;
}

int _validauth(unsigned char *rad, unsigned char *reqauth, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    int result;

    pthread_mutex_lock(&lock);
    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        debugx(1, DBG_ERR, "%s: malloc failed", __func__);

    len = RADLEN(rad);

    result = (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) &&
	      EVP_DigestUpdate(mdctx, rad, 4) &&
	      EVP_DigestUpdate(mdctx, reqauth, 16) &&
	      (len <= 20 || EVP_DigestUpdate(mdctx, rad + 20, len - 20)) &&
	      EVP_DigestUpdate(mdctx, sec, strlen((char *)sec)) &&
	      EVP_DigestFinal_ex(mdctx, hash, &len) &&
	      len == 16 &&
	      !memcmp(hash, rad + 4, 16));
    EVP_MD_CTX_free(mdctx);
    pthread_mutex_unlock(&lock);
    return result;
}

int _createmessageauth(unsigned char *rad, unsigned char *authattrval, uint8_t *secret) {
    int result = 0;             /* Fail. */
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static HMAC_CTX *hmacctx = NULL;
    unsigned int md_len;

    if (!authattrval)
	return 1;

    pthread_mutex_lock(&lock);
    hmacctx = HMAC_CTX_new();
    if (!hmacctx)
        debugx(1, DBG_ERR, "%s: malloc failed", __func__);

    memset(authattrval, 0, 16);
    md_len = 0;
    HMAC_Init_ex(hmacctx, secret, strlen((char *)secret), EVP_md5(), NULL);
    HMAC_Update(hmacctx, rad, RADLEN(rad));
    HMAC_Final(hmacctx, authattrval, &md_len);
    if (md_len != 16) {
	debug(DBG_WARN, "message auth computation failed");
        goto out;
    }
    result = 1;
out:
    HMAC_CTX_free(hmacctx);
    pthread_mutex_unlock(&lock);
    return result;
}

int _radsign(unsigned char *rad, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    EVP_MD_CTX *mdctx = NULL;
    unsigned int md_len;
    int result;

    pthread_mutex_lock(&lock);
    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        debugx(1, DBG_ERR, "%s: malloc failed", __func__);

    result = (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) &&
	      EVP_DigestUpdate(mdctx, rad, RADLEN(rad)) &&
	      EVP_DigestUpdate(mdctx, sec, strlen((char *)sec)) &&
	      EVP_DigestFinal_ex(mdctx, rad + 4, &md_len) &&
	      md_len == 16);
    EVP_MD_CTX_free(mdctx);
    pthread_mutex_unlock(&lock);
    return result;
}

uint8_t *radmsg2buf(struct radmsg *msg, uint8_t *secret) {
    struct list_node *node;
    struct tlv *tlv;
    int size;
    uint8_t *buf, *p, *msgauth = NULL;

    if (!msg || !msg->attrs)
        return NULL;
    size = 20;
    for (node = list_first(msg->attrs); node; node = list_next(node))
        size += 2 + ((struct tlv *)node->data)->l;
    if (size > 65535)
        return NULL;
    buf = malloc(size);
    if (!buf)
        return NULL;

    p = buf;
    *p++ = msg->code;
    *p++ = msg->id;
    *(uint16_t *)p = htons(size);
    p += 2;
    memcpy(p, msg->auth, 16);
    p += 16;

    for (node = list_first(msg->attrs); node; node = list_next(node)) {
        tlv = (struct tlv *)node->data;
        p = tlv2buf(p, tlv);
	p[-1] += 2;
	if (tlv->t == RAD_Attr_Message_Authenticator && secret)
	    msgauth = p;
        p += tlv->l;
    }
    if (msgauth && !_createmessageauth(buf, msgauth, secret)) {
	free(buf);
	return NULL;
    }
    if (secret) {
	if ((msg->code == RAD_Access_Accept || msg->code == RAD_Access_Reject || msg->code == RAD_Access_Challenge || msg->code == RAD_Accounting_Response || msg->code == RAD_Accounting_Request) && !_radsign(buf, secret)) {
	    free(buf);
	    return NULL;
	}
	if (msg->code == RAD_Accounting_Request)
	    memcpy(msg->auth, buf + 4, 16);
    }
    return buf;
}

/* if secret set we also validate message authenticator if present */
struct radmsg *buf2radmsg(uint8_t *buf, uint8_t *secret, uint8_t *rqauth) {
    struct radmsg *msg;
    uint8_t t, l, *v = NULL, *p, auth[16];
    uint16_t len;
    struct tlv *attr;

    len = RADLEN(buf);
    if (len < 20)
	return NULL;

    if (secret && buf[0] == RAD_Accounting_Request) {
	memset(auth, 0, 16);
	if (!_validauth(buf, auth, secret)) {
	    debug(DBG_WARN, "buf2radmsg: Accounting-Request message authentication failed");
	    return NULL;
	}
    }

    if (rqauth && !_validauth(buf, rqauth, secret)) {
	debug(DBG_WARN, "buf2radmsg: Invalid auth, ignoring reply");
	return NULL;
    }

    msg = radmsg_init(buf[0], buf[1], (uint8_t *)buf + 4);
    if (!msg)
        return NULL;

    p = buf + 20;
    while (p - buf + 2 <= len) {
	t = *p++;
        l = *p++;
	if (l < 2) {
	    debug(DBG_WARN, "buf2radmsg: invalid attribute length %d", l);
	    radmsg_free(msg);
	    return NULL;
	}
	l -= 2;
        if (l) {
            if (p - buf + l > len) {
		debug(DBG_WARN, "buf2radmsg: attribute length %d exceeds packet length", l + 2);
		radmsg_free(msg);
		return NULL;
	    }
            v = p;
            p += l;
        }

	if (t == RAD_Attr_Message_Authenticator && secret) {
	    if (rqauth)
		memcpy(buf + 4, rqauth, 16);
	    if (l != 16 || !_checkmsgauth(buf, v, secret)) {
		debug(DBG_WARN, "buf2radmsg: message authentication failed");
		if (rqauth)
		    memcpy(buf + 4, msg->auth, 16);
		radmsg_free(msg);
		return NULL;
	    }
	    if (rqauth)
		memcpy(buf + 4, msg->auth, 16);
	    debug(DBG_DBG, "buf2radmsg: message auth ok");
	}

        attr = maketlv(t, l, v);
        if (!attr || !radmsg_add(msg, attr)) {
            freetlv(attr);
	    radmsg_free(msg);
	    return NULL;
        }
    }
    return msg;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
