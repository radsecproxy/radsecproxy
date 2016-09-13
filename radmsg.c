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
#include <nettle/hmac.h>
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
    struct hmac_md5_ctx hmacctx;
    uint8_t auth[16], hash[MD5_DIGEST_SIZE];

    pthread_mutex_lock(&lock);

   /* FIXME: Why clearing authattr during hashing? */
    memcpy(auth, authattr, 16);
    memset(authattr, 0, 16);

    hmac_md5_set_key(&hmacctx, strlen((char *) secret), secret);
    hmac_md5_update(&hmacctx, RADLEN(rad), rad);
    hmac_md5_digest(&hmacctx, sizeof(hash), hash);

    memcpy(authattr, auth, 16);

    if (memcmp(auth, hash, 16)) {
	debug(DBG_WARN, "message authenticator, wrong value");
        goto out;
    }
    result = 1;                 /* Success. */

out:
    pthread_mutex_unlock(&lock);
    return result;
}

int _validauth(unsigned char *rad, unsigned char *reqauth, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct md5_ctx mdctx;
    unsigned char hash[MD5_DIGEST_SIZE];
    const unsigned int len = RADLEN(rad);
    int result = 0;             /* Fail. */

    pthread_mutex_lock(&lock);
    md5_init(&mdctx);

    md5_update(&mdctx, 4, rad);
    md5_update(&mdctx, 16, reqauth);
    if (len > 20)
        md5_update(&mdctx, len - 20, rad + 20);
    md5_update(&mdctx, strlen((char *) sec), sec);
    md5_digest(&mdctx, sizeof(hash), hash);

    result = !memcmp(hash, rad + 4, 16);

    pthread_mutex_unlock(&lock);
    return result;
}

int _createmessageauth(unsigned char *rad, unsigned char *authattrval, uint8_t *secret) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct hmac_md5_ctx hmacctx;

    if (!authattrval)
	return 1;

    pthread_mutex_lock(&lock);

    memset(authattrval, 0, 16);
    hmac_md5_set_key(&hmacctx, strlen((char *) secret), secret);
    hmac_md5_update(&hmacctx, RADLEN(rad), rad);
    hmac_md5_digest(&hmacctx, MD5_DIGEST_SIZE, authattrval);

    pthread_mutex_unlock(&lock);
    return 1;
}

int _radsign(unsigned char *rad, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct md5_ctx mdctx;

    pthread_mutex_lock(&lock);

    md5_init(&mdctx);
    md5_update(&mdctx, RADLEN(rad), rad);
    md5_update(&mdctx, strlen((char *) sec), sec);
    md5_digest(&mdctx, MD5_DIGEST_SIZE, rad + 4);

    pthread_mutex_unlock(&lock);
    return 1;
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
