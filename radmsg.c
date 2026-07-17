/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include "debug.h"
#include "list.h"
#include "raddict.h"
#include "radmsg.h"
#include "util.h"
#include "utilcrypto.h"
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
        memset(msg, 0, sizeof(struct radmsg));
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
        radmsg_free(msg);
        return NULL;
    }
    return msg;
}

int radmsg_add(struct radmsg *msg, struct tlv *attr, uint8_t front) {
    if (!msg || !msg->attrs)
        return 0;
    if (!attr || attr->l > RAD_Max_Attr_Value_Length)
        return 0;
    return front ? list_push_front(msg->attrs, attr) : list_push(msg->attrs, attr);
}

/** Return a new list with all tlv's in \a msg of type \a type. The
 * caller is responsible for freeing the list by calling \a
 * list_free(). */
struct list *radmsg_getalltype(const struct radmsg *msg, uint8_t type) {
    struct list *list = NULL;
    struct list_node *node = NULL;

    if (!msg || !msg->attrs)
        return NULL;
    list = list_create();
    if (!list)
        return NULL;

    for (node = list_first(msg->attrs); node; node = list_next(node))
        if (((struct tlv *)node->data)->t == type)
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
                      uint8_t type) {
    struct list_node *node = NULL;
    struct list *list = radmsg_getalltype(src, type);
    struct tlv *copy;
    int n = 0;

    for (node = list_first(list); node; node = list_next(node)) {
        copy = copytlv((struct tlv *)node->data);
        if (!copy || radmsg_add(dst, copy, 0) != 1) {
            freetlv(copy);
            n = -1;
            break;
        }
        n++;
    }
    list_free(list);
    return n;
}

uint8_t *tlv2buf(uint8_t *p, const struct tlv *tlv) {
    p[0] = tlv->t;
    p[1] = tlv->l + 2;
    if (tlv->l) {
        if (tlv->v)
            memcpy(p + 2, tlv->v, tlv->l);
        else
            memset(p + 2, 0, tlv->l);
    }
    return p;
}

int radmsg2buf(struct radmsg *msg, uint8_t *secret, int secret_len, uint8_t **buf) {
    struct list_node *node;
    struct tlv *tlv;
    int size;
    uint16_t netshort;
    uint8_t *p, *pmsgauth = NULL;

    if (!msg || !msg->attrs)
        return -1;
    size = RADHDRLEN;
    for (node = list_first(msg->attrs); node; node = list_next(node))
        size += ATTRHDRLEN + ((struct tlv *)node->data)->l;
    if (size > RAD_Max_Length || size < 0)
        return -1;
    *buf = malloc(size);
    if (!*buf)
        return -1;

    RADCODE(*buf) = msg->code;
    RADID(*buf) = msg->id;
    netshort = htons(size);
    memcpy(*buf + 2, &netshort, sizeof(uint16_t));
    memcpy(RADAUTH(*buf), msg->auth, RADAUTHLEN);

    p = *buf + RADHDRLEN;
    for (node = list_first(msg->attrs); node; node = list_next(node)) {
        tlv = (struct tlv *)node->data;
        p = tlv2buf(p, tlv);
        if (tlv->t == RAD_Attr_Message_Authenticator && secret)
            pmsgauth = ATTRVAL(p);
        p += tlv->l + 2;
    }
    if (secret && secret_len > 0 && !radmsgsign(*buf, size, secret, secret_len, pmsgauth, msg->auth)) {
        debug(DBG_ERR, "radmsg2buf: calculating signatures failed");
        free(*buf);
        return -1;
    }
    memcpy(msg->auth, RADAUTH(*buf), RADAUTHLEN);
    return size;
}

/* if secret set we also validate message-authenticator if present */
struct radmsg *buf2radmsg(uint8_t *buf, int len, uint8_t *secret, int secret_len, uint8_t *rqauth) {
    struct radmsg *msg;
    uint8_t *p, *pmsgauth = NULL;
    struct tlv *attr;

    if (len != RADLEN(buf)) {
        debug(DBG_WARN, "buf2radmsg: length field does not match buffer length");
        return NULL;
    }

    p = buf + RADHDRLEN;
    while (p - buf + ATTRHDRLEN <= len) {
        if (ATTRLEN(p) < ATTRHDRLEN) {
            debug(DBG_WARN, "buf2radmsg: attribute %d: invalid length %d", ATTRTYPE(p), ATTRLEN(p));
            return NULL;
        }
        if (p - buf + ATTRLEN(p) > len) {
            debug(DBG_WARN, "buf2radmsg: attribute %d: length %d exceeds packet length", ATTRTYPE(p), ATTRLEN(p));
            return NULL;
        }
        if (ATTRTYPE(p) == RAD_Attr_Message_Authenticator) {
            if (pmsgauth) {
                debug(DBG_WARN, "buf2radmsg: multiple message-authenticator found");
                return NULL;
            }
            if (ATTRLEN(p) != RADAUTHLEN + ATTRHDRLEN) {
                debug(DBG_WARN, "buf2radmsg: invalid message-authenticator length");
                return NULL;
            }
            pmsgauth = ATTRVAL(p);
        }
        p += ATTRLEN(p);
    }
    if (p - buf != len) {
        debug(DBG_WARN, "buf2radmsg: attributes did not fill packet exactly");
        return NULL;
    }

    if (secret && secret_len > 0) {
        uint8_t auth[RADAUTHLEN], msgauth[RADAUTHLEN];

        memcpy(auth, RADAUTH(buf), RADAUTHLEN);
        if (pmsgauth)
            memcpy(msgauth, pmsgauth, RADAUTHLEN);

        if (!radmsgsign(buf, len, secret, secret_len, pmsgauth, rqauth)) {
            debug(DBG_ERR, "buf2radmsg: calculating signatures failed");
            return NULL;
        }

        if (memcmp(auth, RADAUTH(buf), RADAUTHLEN) != 0) {
            debug(DBG_WARN, "buf2radmsg: authenticator invalid (%s id %d)", radmsgtype2string(RADCODE(buf)), RADID(buf));
            return NULL;
        }
        if (pmsgauth && memcmp(msgauth, pmsgauth, 16) != 0) {
            debug(DBG_WARN, "buf2radmsg: message authenticator invalid (%s id %d)", radmsgtype2string(RADCODE(buf)), RADID(buf));
            return NULL;
        }
    }

    msg = radmsg_init(RADCODE(buf), RADID(buf), RADAUTH(buf));
    if (!msg)
        return NULL;

    for (p = buf + RADHDRLEN; p - buf < len; p += ATTRLEN(p)) {
        attr = maketlv(ATTRTYPE(p), ATTRLEN(p), ATTRVAL(p));
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
   If type is found and < 256, 1 is returned.
   Otherwise, 0 is returned.
*/
/* should accept both names and numeric values, only numeric right now */
int vattrname2val(char *attrname, uint32_t *vendor, uint32_t *type) {
    char *s;

    *vendor = atoi(attrname);
    s = strchr(attrname, ':');
    if (!s) { /* Only vendor was found.  */
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
struct tlv *makevendortlv(uint32_t vendor, struct tlv *attr) {
    struct tlv *newtlv = NULL;
    size_t l;
    uint8_t *v;

    if (!attr)
        return NULL;
    if ((l = attr->l + 6) > RAD_Max_Attr_Value_Length)
        return NULL;
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

/**
 * @brief verify eap message attributes for correct format (length)
 * 
 * @param msg the messageto verify
 * @return int 1 if correct (or no eap attributes), 0 if format error
 */
int verifyeapformat(struct radmsg *msg) {
    struct list *eap_attrs;
    struct list_node *node;
    size_t eap_len = 0, attr_len = 0;
    uint8_t *val;
    int ret = 1;

    if (!(eap_attrs = radmsg_getalltype(msg, RAD_Attr_EAP_Message)))
        return 1;

    if (!(node = list_first(eap_attrs))) {
        ret = 1;
        goto exit;
    }

    if (((struct tlv *)node->data)->l < 4) {
        debug(DBG_DBG, "verifyeapformat: first eap attribute too short");
        ret = 0;
        goto exit;
    }

    val = ((struct tlv *)node->data)->v;
    eap_len = (uint16_t)(val[2] << 8 | val[3]);
    for (; node; node = list_next(node)) {
        struct tlv *attr = (struct tlv *)node->data;
        if (attr->l == 0) {
            debug(DBG_DBG, "verifyeapformat: empty eap attribute");
            ret = 0;
            goto exit;
        }
        attr_len += attr->l;
    }
    if (eap_len != attr_len) {
        debug(DBG_DBG, "verifyeapformat: eap length (%zu) does not match attribute content length (%zu)", eap_len, attr_len);
        ret = 0;
        goto exit;
    }

exit:
    list_free(eap_attrs);
    return ret;
}

const char *radmsgtype2string(uint8_t code) {
    static const char *rad_msg_names[] = {
        "", "Access-Request", "Access-Accept", "Access-Reject",
        "Accounting-Request", "Accounting-Response", "", "",
        "", "", "", "Access-Challenge",
        "Status-Server", "Status-Client"};
    return code < 14 && *rad_msg_names[code] ? rad_msg_names[code] : "Unknown";
}

const char *attrval2strdict(struct tlv *attr) {
    uint32_t val;

    if (!attr)
        return NULL;
    val = tlv2longint(attr);
    switch (attr->t) {
    case RAD_Attr_Acct_Status_Type:
        if (val < sizeof(RAD_Attr_Acct_Status_Type_Dict) / sizeof(RAD_Attr_Acct_Status_Type_Dict[0]))
            return RAD_Attr_Acct_Status_Type_Dict[val] ? RAD_Attr_Acct_Status_Type_Dict[val] : RAD_Attr_Dict_Undef;
        break;

    case RAD_Attr_Acct_Terminate_Cause:
        if (val < sizeof(RAD_Attr_Acct_Terminate_Cause_Dict) / sizeof(RAD_Attr_Acct_Terminate_Cause_Dict[0]))
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
