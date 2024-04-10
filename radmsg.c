/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2023, SWITCH */
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
#include "radmsg.h"
#include "debug.h"
#include <pthread.h>
#include <nettle/hmac.h>
#include <openssl/rand.h>
#include "raddict.h"
#include "util.h"

/* radius message length is a 16bit value starting at byte 2, in network order*/
#define RADLEN(buf) ntohs(*(uint16_t *)(buf+2))

/**
 * @brief Get the length of a radius message form its raw buffer.
 * Note the buffer must contain at least the first 4 bytes.
 * 
 * @param buf raw message buffer
 * @return int the length of the radius message if valid, or its negative value if invalid.
 * A 0 value is also consiedered invalid.
 */
int get_checked_rad_length(uint8_t *buf) {
    int len = RADLEN(buf);
    if (len < RAD_Min_Length || len > RAD_Max_Length) {
        return -len;
    }
    return len;
}

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

int radmsg_add(struct radmsg *msg, struct tlv *attr, uint8_t front) {
    if (!msg || !msg->attrs)
        return 1;
    if (!attr || attr->l > RAD_Max_Attr_Value_Length)
        return 0;
    return front? list_push_front(msg->attrs, attr) : list_push(msg->attrs, attr);
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
        if (radmsg_add(dst, copytlv((struct tlv *) node->data),0) != 1) {
            n = -1;
            break;
        }
        n++;
    }
    list_free(list);
    return n;
}

int _checkmsgauth(unsigned char *rad, int radlen, uint8_t *authattr, uint8_t *secret, int secret_len) {
    int result = 0;             /* Fail. */
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct hmac_md5_ctx hmacctx;
    uint8_t auth[16], hash[MD5_DIGEST_SIZE];

    pthread_mutex_lock(&lock);

   /* FIXME: Why clearing authattr during hashing? */
    memcpy(auth, authattr, 16);
    memset(authattr, 0, 16);

    hmac_md5_set_key(&hmacctx, secret_len, secret);
    hmac_md5_update(&hmacctx, radlen, rad);
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

int _validauth(unsigned char *rad, int len, unsigned char *reqauth, unsigned char *sec, int sec_len) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct md5_ctx mdctx;
    unsigned char hash[MD5_DIGEST_SIZE];
    int result = 0;             /* Fail. */

    pthread_mutex_lock(&lock);
    md5_init(&mdctx);

    md5_update(&mdctx, 4, rad);
    md5_update(&mdctx, 16, reqauth);
    if (len > 20)
        md5_update(&mdctx, len - 20, rad + 20);
    md5_update(&mdctx, sec_len, sec);
    md5_digest(&mdctx, sizeof(hash), hash);

    result = !memcmp(hash, rad + 4, 16);

    pthread_mutex_unlock(&lock);
    return result;
}

int _createmessageauth(unsigned char *rad, int radlen, unsigned char *authattrval, uint8_t *secret, int secret_len) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct hmac_md5_ctx hmacctx;

    if (!authattrval)
	return 1;

    pthread_mutex_lock(&lock);

    memset(authattrval, 0, 16);
    hmac_md5_set_key(&hmacctx, secret_len, secret);
    hmac_md5_update(&hmacctx, radlen, rad);
    hmac_md5_digest(&hmacctx, MD5_DIGEST_SIZE, authattrval);

    pthread_mutex_unlock(&lock);
    return 1;
}

int _radsign(unsigned char *rad, int radlen, unsigned char *sec, int sec_len) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct md5_ctx mdctx;

    pthread_mutex_lock(&lock);

    md5_init(&mdctx);
    md5_update(&mdctx, radlen, rad);
    md5_update(&mdctx, sec_len, sec);
    md5_digest(&mdctx, MD5_DIGEST_SIZE, rad + 4);

    pthread_mutex_unlock(&lock);
    return 1;
}

uint8_t *tlv2buf(uint8_t *p, const struct tlv *tlv) {
    p[0] = tlv->t;
    p[1] = tlv->l+2;
    if (tlv->l) {
	if (tlv->v)
	    memcpy(p+2, tlv->v, tlv->l);
	else
	    memset(p+2, 0, tlv->l);
    }
    return p;
}

int radmsg2buf(struct radmsg *msg, uint8_t *secret, int secret_len, uint8_t **buf) {
    struct list_node *node;
    struct tlv *tlv;
    int size;
    uint8_t *p, *msgauth = NULL;

    if (!msg || !msg->attrs)
        return -1;
    size = 20;
    for (node = list_first(msg->attrs); node; node = list_next(node))
        size += 2 + ((struct tlv *)node->data)->l;
    if (size > 65535)
        return -1;
    *buf = malloc(size);
    if (!*buf)
        return -1;

    p = *buf;
    *p++ = msg->code;
    *p++ = msg->id;
    *(uint16_t *)p = htons(size);
    p += 2;
    memcpy(p, msg->auth, 16);
    p += 16;

    for (node = list_first(msg->attrs); node; node = list_next(node)) {
        tlv = (struct tlv *)node->data;
        p = tlv2buf(p, tlv);
        if (tlv->t == RAD_Attr_Message_Authenticator && secret)
            msgauth = ATTRVAL(p);
        p += tlv->l + 2;
    }
    if (msgauth && !_createmessageauth(*buf, size, msgauth, secret, secret_len)) {
	free(*buf);
	return -1;
    }
    if (secret) {
	if ((msg->code == RAD_Access_Accept || msg->code == RAD_Access_Reject || msg->code == RAD_Access_Challenge || msg->code == RAD_Accounting_Response || msg->code == RAD_Accounting_Request) && !_radsign(*buf, size, secret, secret_len)) {
	    free(*buf);
	    return -1;
	}
	if (msg->code == RAD_Accounting_Request)
	    memcpy(msg->auth, *buf + 4, 16);
    }
    return size;
}

/* if secret set we also validate message authenticator if present */
struct radmsg *buf2radmsg(uint8_t *buf, int len, uint8_t *secret, int secret_len, uint8_t *rqauth) {
    struct radmsg *msg;
    uint8_t t, l, *v = NULL, *p, auth[16];
    struct tlv *attr;

    if (len != RADLEN(buf)) {
        debug(DBG_WARN, "buf2radmsg: length field does not match buffer length, ignoring message");
        return NULL;
    }

    if (secret && buf[0] == RAD_Accounting_Request) {
	memset(auth, 0, 16);
	if (!_validauth(buf, len, auth, secret, secret_len)) {
	    debug(DBG_WARN, "buf2radmsg: Accounting-Request message authentication failed");
	    return NULL;
	}
    }

    if (rqauth && secret && !_validauth(buf, len, rqauth, secret, secret_len)) {
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
	if (l < 2 || l > 255) {
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
	    if (l != 16 || !_checkmsgauth(buf, len, v, secret, secret_len)) {
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
        if (!attr || !radmsg_add(msg, attr, 0)) {
            freetlv(attr);
	    radmsg_free(msg);
	    return NULL;
        }
    }
    return msg;
}

/* should accept both names and numeric values, only numeric right now */
uint8_t attrname2val(char *attrname) {
    int val = 0;

    val = atoi(attrname);
    return val > 0 && val < 256 ? val : 0;
}

/* ATTRNAME is on the form vendor[:type].
   If only vendor is found, TYPE is set to 256 and 1 is returned.
   If type is >= 256, 1 is returned.
   Otherwise, 0 is returned.
*/
/* should accept both names and numeric values, only numeric right now */
int vattrname2val(char *attrname, uint32_t *vendor, uint32_t *type) {
    char *s;

    *vendor = atoi(attrname);
    s = strchr(attrname, ':');
    if (!s) {			/* Only vendor was found.  */
	*type = 256;
	return 1;
    }
    *type = atoi(s + 1);
    return *type < 256;
}

int attrvalidate(unsigned char *attrs, int length) {
    while (length > 1) {
	if (ATTRLEN(attrs) < 2) {
	    debug(DBG_INFO, "attrvalidate: invalid attribute length %d", ATTRLEN(attrs));
	    return 0;
	}
	length -= ATTRLEN(attrs);
	if (length < 0) {
	    debug(DBG_INFO, "attrvalidate: attribute length %d exceeds packet length", ATTRLEN(attrs));
	    return 0;
	}
	attrs += ATTRLEN(attrs);
    }
    if (length)
	debug(DBG_INFO, "attrvalidate: malformed packet? remaining byte after last attribute");
    return 1;
}

/** Create vendor specific tlv with ATTR.  ATTR is consumed (freed) if
 * all is well with the new tlv, i.e. if the function returns
 * !NULL.  */
struct tlv *makevendortlv(uint32_t vendor, struct tlv *attr){
    struct tlv *newtlv = NULL;
    uint8_t l, *v;

    if (!attr || attr->l > (RAD_Max_Attr_Value_Length - 6))
        return NULL;
    l = attr->l + 2 + 4;
    v = malloc(l);
    if (v) {
        vendor = htonl(vendor & 0x00ffffff); /* MSB=0 according to RFC 2865. */
        memcpy(v, &vendor, 4);
        tlv2buf(v + 4, attr);
        newtlv = maketlv(RAD_Attr_Vendor_Specific, l, v);
        free(v);
        if (newtlv)
            freetlv(attr);
    }
    return newtlv;
}

int resizeattr(struct tlv *attr, uint8_t newlen) {
    if (newlen > RAD_Max_Attr_Value_Length)
        return 0;

    if (resizetlv(attr, newlen))
        return 1;
    return 0;
}

const char* attrval2strdict(struct tlv *attr) {
    uint32_t val;

    if(!attr) return NULL;
    val = tlv2longint(attr);
    switch (attr->t) {
        case RAD_Attr_Acct_Status_Type:
            if(val < sizeof(RAD_Attr_Acct_Status_Type_Dict)/sizeof(RAD_Attr_Acct_Status_Type_Dict[0]))
                return RAD_Attr_Acct_Status_Type_Dict[val] ? RAD_Attr_Acct_Status_Type_Dict[val] : RAD_Attr_Dict_Undef;
            break;

        case RAD_Attr_Acct_Terminate_Cause:
            if(val < sizeof(RAD_Attr_Acct_Terminate_Cause_Dict)/sizeof(RAD_Attr_Acct_Terminate_Cause_Dict[0]))
                return RAD_Attr_Acct_Terminate_Cause_Dict[val] ? RAD_Attr_Acct_Terminate_Cause_Dict[val] : RAD_Attr_Dict_Undef;
            break;

        default:
            break;
    }
    return NULL;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
