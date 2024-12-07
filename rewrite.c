/* Copyright (c) 2019, SWITCH */
/* See LICENSE for licensing information. */

#include "rewrite.h"
#include "debug.h"
#include "gconfig.h"
#include "hash.h"
#include "list.h"
#include "radmsg.h"
#include "util.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

static struct hash *rewriteconfs;

/** Extract attributes from string NAMEVAL, create a struct tlv and
 * return the tlv.  If VENDOR_FLAG, NAMEVAL is on the form
 * "<vendor>:<name>:<val>" and otherwise it's "<name>:<val>".  Return
 * NULL if fields are missing or if conversion fails.
 *
 * FIXME: Should accept both names and numeric values, only numeric
 * right now */
struct tlv *extractattr(char *nameval, char vendor_flag) {
    int len, name = 0;
    int vendor = 0; /* Vendor 0 is reserved, see RFC 1700.  */
    uint32_t ival = 0;
    char *s, *s2;
    struct tlv *a;

    s = strchr(nameval, ':');
    if (!s)
        return NULL;
    name = atoi(nameval);

    if (vendor_flag) {
        s2 = strchr(s + 1, ':');
        if (!s2)
            return NULL;
        vendor = name;
        name = atoi(s + 1);
        s = s2;
    }

    s++;
    if (isdigit((int)*s)) {
        ival = atoi(s);
        ival = htonl(ival);
        len = 4;
        s = (char *)&ival;
    } else {
        if (*s == '\'')
            s++;

        len = unhex(s, 1);
        if (len > 253)
            return NULL;
    }

    if (name < 1 || name > 255)
        return NULL;
    a = malloc(sizeof(struct tlv));
    if (!a)
        return NULL;

    a->v = (uint8_t *)stringcopy(s, len);
    if (!a->v) {
        free(a);
        return NULL;
    }
    a->t = name;
    a->l = len;

    if (vendor_flag)
        a = makevendortlv(vendor, a);

    return a;
}

/* should accept both names and numeric values, only numeric right now */
struct modattr *extractmodattr(char *nameval) {
    int name = 0;
    char *s, *t;
    struct modattr *m;

    if (!strncasecmp(nameval, "User-Name:/", 11)) {
        s = nameval + 11;
        name = 1;
    } else {
        s = strchr(nameval, ':');
        name = atoi(nameval);
        if (!s || name < 1 || name > 255 || s[1] != '/')
            return NULL;
        s += 2;
    }
    /* regexp, remove optional trailing / if present */
    if (s[strlen(s) - 1] == '/')
        s[strlen(s) - 1] = '\0';

    for (t = strchr(s, '/'); t; t = strchr(t + 1, '/'))
        if (t == s || t[-1] != '\\')
            break;
    if (!t)
        return NULL;
    *t = '\0';
    t++;

    m = malloc(sizeof(struct modattr));
    if (!m) {
        debug(DBG_ERR, "malloc failed");
        return NULL;
    }
    m->t = name;

    m->replacement = stringcopy(t, 0);
    if (!m->replacement) {
        free(m);
        debug(DBG_ERR, "malloc failed");
        return NULL;
    }

    m->regex = malloc(sizeof(regex_t));
    if (!m->regex) {
        free(m->replacement);
        free(m);
        debug(DBG_ERR, "malloc failed");
        return NULL;
    }

    if (regcomp(m->regex, s, REG_ICASE | REG_EXTENDED)) {
        free(m->regex);
        free(m->replacement);
        free(m);
        debug(DBG_ERR, "failed to compile regular expression %s", s);
        return NULL;
    }

    return m;
}

struct modattr *extractmodvattr(char *nameval) {
    uint32_t vendor;
    char *s;
    struct modattr *modvattr;

    s = strchr(nameval, ':');
    vendor = atoi(nameval);
    if (!s || !vendor || !strchr(s + 1, ':'))
        return NULL;
    modvattr = extractmodattr(s + 1);
    if (modvattr)
        modvattr->vendor = vendor;
    return modvattr;
}

void addrewrite(char *value, uint8_t whitelist_mode, char **rmattrs, char **rmvattrs, char **addattrs,
                char **addvattrs, char **modattrs, char **modvattrs, char **supattrs, char **supvattrs) {
    struct rewrite *rewrite = NULL;
    int i, n;
    uint8_t *rma = NULL;
    uint32_t *p, *rmva = NULL;
    struct list *adda = NULL, *moda = NULL, *modva = NULL, *supa = NULL;
    struct tlv *a;
    struct modattr *m;

    if (rmattrs) {
        for (n = 0; rmattrs[n];)
            n++;
        rma = calloc(n + 1, sizeof(uint8_t));
        if (!rma)
            debugx(1, DBG_ERR, "malloc failed");

        for (i = 0; i < n; i++)
            if (!(rma[i] = attrname2val(rmattrs[i])))
                debugx(1, DBG_ERR, "addrewrite: removing invalid attribute %s", rmattrs[i]);
        freegconfmstr(rmattrs);
        rma[i] = 0;
    }

    if (rmvattrs) {
        for (n = 0; rmvattrs[n];)
            n++;
        rmva = calloc(2 * n + 1, sizeof(uint32_t));
        if (!rmva)
            debugx(1, DBG_ERR, "malloc failed");

        for (p = rmva, i = 0; i < n; i++, p += 2)
            if (!vattrname2val(rmvattrs[i], p, p + 1))
                debugx(1, DBG_ERR, "addrewrite: removing invalid vendor attribute %s", rmvattrs[i]);
        freegconfmstr(rmvattrs);
        *p = 0;
    }

    if (addattrs) {
        adda = list_create();
        if (!adda)
            debugx(1, DBG_ERR, "malloc failed");
        for (i = 0; addattrs[i]; i++) {
            a = extractattr(addattrs[i], 0);
            if (!a)
                debugx(1, DBG_ERR, "addrewrite: adding invalid attribute %s", addattrs[i]);
            if (!list_push(adda, a))
                debugx(1, DBG_ERR, "malloc failed");
        }
        freegconfmstr(addattrs);
    }

    if (addvattrs) {
        if (!adda)
            adda = list_create();
        if (!adda)
            debugx(1, DBG_ERR, "malloc failed");
        for (i = 0; addvattrs[i]; i++) {
            a = extractattr(addvattrs[i], 1);
            if (!a)
                debugx(1, DBG_ERR, "addrewrite: adding invalid vendor attribute %s", addvattrs[i]);
            if (!list_push(adda, a))
                debugx(1, DBG_ERR, "malloc failed");
        }
        freegconfmstr(addvattrs);
    }

    if (modattrs) {
        moda = list_create();
        if (!moda)
            debugx(1, DBG_ERR, "malloc failed");
        for (i = 0; modattrs[i]; i++) {
            m = extractmodattr(modattrs[i]);
            if (!m)
                debugx(1, DBG_ERR, "addrewrite: modifying invalid attribute %s", modattrs[i]);
            if (!list_push(moda, m))
                debugx(1, DBG_ERR, "malloc failed");
        }
        freegconfmstr(modattrs);
    }

    if (modvattrs) {
        modva = list_create();
        if (!modva)
            debugx(1, DBG_ERR, "malloc failed");
        for (i = 0; modvattrs[i]; i++) {
            m = extractmodvattr(modvattrs[i]);
            if (!m)
                debugx(1, DBG_ERR, "addrewrite: modifying invalid vendor attribute %s", modvattrs[i]);
            if (!list_push(modva, m))
                debugx(1, DBG_ERR, "malloc failed");
        }
        freegconfmstr(modvattrs);
    }

    if (supattrs) {
        supa = list_create();
        if (!supa)
            debugx(1, DBG_ERR, "malloc failed");
        for (i = 0; supattrs[i]; i++) {
            a = extractattr(supattrs[i], 0);
            if (!a)
                debugx(1, DBG_ERR, "addrewrite: adding invalid attribute %s", supattrs[i]);
            if (!list_push(supa, a))
                debugx(1, DBG_ERR, "malloc failed");
        }
        freegconfmstr(supattrs);
    }

    if (supvattrs) {
        if (!supa)
            supa = list_create();
        if (!supa)
            debugx(1, DBG_ERR, "malloc failed");
        for (i = 0; supvattrs[i]; i++) {
            a = extractattr(supvattrs[i], 1);
            if (!a)
                debugx(1, DBG_ERR, "addrewrite: adding invalid vendor attribute %s", supvattrs[i]);
            if (!list_push(supa, a))
                debugx(1, DBG_ERR, "malloc failed");
        }
        freegconfmstr(supvattrs);
    }

    if (rma || rmva || adda || moda || modva || supa) {
        rewrite = malloc(sizeof(struct rewrite));
        if (!rewrite)
            debugx(1, DBG_ERR, "malloc failed");
        rewrite->whitelist_mode = whitelist_mode;
        rewrite->removeattrs = rma;
        rewrite->removevendorattrs = rmva;
        rewrite->addattrs = adda;
        rewrite->modattrs = moda;
        rewrite->modvattrs = modva;
        rewrite->supattrs = supa;
    }

    if (!rewriteconfs)
        rewriteconfs = hash_create();
    if (!hash_insert(rewriteconfs, value, strlen(value), rewrite))
        debugx(1, DBG_ERR, "malloc failed");
    debug(DBG_DBG, "addrewrite: added rewrite block %s", value);
}

struct rewrite *getrewrite(char *alt1, char *alt2) {
    struct rewrite *r;

    if (alt1)
        if ((r = hash_read(rewriteconfs, alt1, strlen(alt1))))
            return r;
    if (alt2)
        if ((r = hash_read(rewriteconfs, alt2, strlen(alt2))))
            return r;
    return NULL;
}

int findvendorsubattr(uint32_t *attrs, uint32_t vendor, uint32_t subattr) {
    if (!attrs)
        return 0;

    for (; attrs[0]; attrs += 2)
        if (attrs[0] == vendor && attrs[1] == subattr)
            return 1;
    return 0;
}

/* returns 1 if entire element is to be removed, else 0 */
int dovendorrewriterm(struct tlv *attr, uint32_t *removevendorattrs, int inverted) {
    uint8_t alen, sublen;
    uint32_t vendor;
    uint8_t *subattrs;

    if (!removevendorattrs || attr->l <= 4)
        return 0;

    memcpy(&vendor, attr->v, 4);
    vendor = ntohl(vendor);
    while (*removevendorattrs && *removevendorattrs != vendor)
        removevendorattrs += 2;
    if (!*removevendorattrs)
        return 0;

    if (findvendorsubattr(removevendorattrs, vendor, 256))
        return 1; /* remove entire vendor attribute */

    sublen = attr->l - 4;
    subattrs = attr->v + 4;

    if (!attrvalidate(subattrs, sublen)) {
        debug(DBG_INFO, "dovendorrewrite: vendor attribute validation failed, no rewrite");
        return 0;
    }

    while (sublen > 1) {
        alen = ATTRLEN(subattrs);
        sublen -= alen;
        if (!!findvendorsubattr(removevendorattrs, vendor, ATTRTYPE(subattrs)) != !!inverted) {
            memmove(subattrs, subattrs + alen, sublen);
            attr->l -= alen;
        } else
            subattrs += alen;
    }
    if ((attr->l <= 4) != !!inverted)
        return 1;
    return 0;
}

/*if inverted is true, remove all attributes except those listed */
void dorewriterm(struct radmsg *msg, uint8_t *rmattrs, uint32_t *rmvattrs, int inverted) {
    struct list_node *n, *p;
    struct tlv *attr;

    p = NULL;
    n = list_first(msg->attrs);
    while (n) {
        attr = (struct tlv *)n->data;
        if (((rmattrs && strchr((char *)rmattrs, attr->t)) ||
             (rmvattrs && attr->t == RAD_Attr_Vendor_Specific && dovendorrewriterm(attr, rmvattrs, inverted))) != !!inverted) {
            list_removedata(msg->attrs, attr);
            freetlv(attr);
            n = p ? list_next(p) : list_first(msg->attrs);
        } else {
            p = n;
            n = list_next(n);
        }
    }
}

int dorewritemodattr(struct tlv *attr, struct modattr *modattr) {
    size_t nmatch = 10, reslen = 0, start = 0;
    regmatch_t pmatch[10], *pfield;
    int i;
    char *in, *out;

    in = stringcopy((char *)attr->v, attr->l);
    if (!in)
        return 0;

    if (regexec(modattr->regex, in, nmatch, pmatch, 0)) {
        free(in);
        return 1;
    }

    out = modattr->replacement;

    for (i = start; out[i]; i++) {
        if (out[i] == '\\' && out[i + 1] >= '1' && out[i + 1] <= '9') {
            pfield = &pmatch[out[i + 1] - '0'];
            if (pfield->rm_so >= 0) {
                reslen += i - start + pfield->rm_eo - pfield->rm_so;
                start = i + 2;
            }
            i++;
        }
    }
    reslen += i - start;
    if (!resizeattr(attr, reslen)) {
        debug(DBG_INFO, "rewritten attribute to length %zu failed, discarding message", reslen);
        free(in);
        return 0;
    }

    start = 0;
    reslen = 0;
    for (i = start; out[i]; i++) {
        if (out[i] == '\\' && out[i + 1] >= '1' && out[i + 1] <= '9') {
            pfield = &pmatch[out[i + 1] - '0'];
            if (pfield->rm_so >= 0) {
                memcpy(attr->v + reslen, out + start, i - start);
                reslen += i - start;
                memcpy(attr->v + reslen, in + pfield->rm_so, pfield->rm_eo - pfield->rm_so);
                reslen += pfield->rm_eo - pfield->rm_so;
                start = i + 2;
            }
            i++;
        }
    }
    free(in);

    memcpy(attr->v + reslen, out + start, i - start);
    return 1;
}

int replacesubtlv(struct tlv *vendortlv, uint8_t *p, struct tlv *newtlv) {
    int size_diff;
    uint8_t rem_size, *next_attr;

    size_diff = newtlv->l - ATTRLEN(p);
    next_attr = p + ATTRLEN(p);
    rem_size = (vendortlv->v + vendortlv->l) - next_attr;

    if (size_diff < 0)
        memmove(next_attr + size_diff, next_attr, rem_size);
    if (!resizeattr(vendortlv, vendortlv->l + size_diff))
        return 0;
    if (size_diff > 0)
        memmove(next_attr + size_diff, next_attr, rem_size);

    tlv2buf(p, newtlv);
    return 1;
}

int dorewritemodvattr(struct tlv *vendortlv, struct modattr *modvattr) {
    struct tlv *tmpattr;
    int offset;

    if (vendortlv->l <= 4 || !attrvalidate(vendortlv->v + 4, vendortlv->l - 4))
        return 0;
    for (offset = 4; offset < vendortlv->l; offset += ATTRLEN(vendortlv->v + offset)) {
        if (ATTRTYPE(vendortlv->v + offset) == modvattr->t) {
            tmpattr = maketlv(ATTRTYPE(vendortlv->v + offset), ATTRVALLEN(vendortlv->v + offset), ATTRVAL(vendortlv->v + offset));
            if (!tmpattr)
                return 0;
            if (dorewritemodattr(tmpattr, modvattr)) {
                int size_diff = tmpattr->l - ATTRVALLEN(vendortlv->v + offset);
                int rem_size = vendortlv->l - offset - ATTRLEN(vendortlv->v + offset);
                uint8_t *next;

                if (size_diff > 0)
                    if (!resizeattr(vendortlv, vendortlv->l + size_diff)) {
                        freetlv(tmpattr);
                        return 0;
                    }
                next = vendortlv->v + offset + ATTRLEN(vendortlv->v + offset);
                memmove(next + size_diff, next, rem_size);
                if (size_diff < 0)
                    if (!resizeattr(vendortlv, vendortlv->l + size_diff)) {
                        freetlv(tmpattr);
                        return 0;
                    }

                tlv2buf(vendortlv->v + offset, tmpattr);
            } else {
                freetlv(tmpattr);
                return 0;
            }
            freetlv(tmpattr);
        }
    }
    return 1;
}

int dorewritemod(struct radmsg *msg, struct list *modattrs, struct list *modvattrs) {
    struct list_node *n, *m;
    uint32_t vendor;

    for (n = list_first(msg->attrs); n; n = list_next(n)) {
        struct tlv *attr = (struct tlv *)n->data;
        if (attr->t == RAD_Attr_Vendor_Specific) {
            memcpy(&vendor, attr->v, 4);
            vendor = ntohl(vendor);
            for (m = list_first(modvattrs); m; m = list_next(m)) {
                if (vendor == ((struct modattr *)m->data)->vendor &&
                    !dorewritemodvattr(attr, (struct modattr *)m->data))
                    return 0;
            }
        } else {
            for (m = list_first(modattrs); m; m = list_next(m))
                if (((struct tlv *)n->data)->t == ((struct modattr *)m->data)->t &&
                    !dorewritemodattr((struct tlv *)n->data, (struct modattr *)m->data))
                    return 0;
        }
    }
    return 1;
}

int dorewriteadd(struct radmsg *msg, struct list *addattrs) {
    struct list_node *n;
    struct tlv *a;

    for (n = list_first(addattrs); n; n = list_next(n)) {
        a = copytlv((struct tlv *)n->data);
        if (!a)
            return 0;
        if (!radmsg_add(msg, a, 0)) {
            freetlv(a);
            return 0;
        }
    }
    return 1;
}

int dorewritesupattr(struct radmsg *msg, struct tlv *supattr) {
    struct list_node *p;
    struct tlv *attr;
    uint8_t exist = 0, *vendortype, *v;

    for (p = list_first(msg->attrs); p; p = list_next(p)) {
        attr = (struct tlv *)p->data;
        if (attr->t == supattr->t && attr->t != RAD_Attr_Vendor_Specific) {
            exist = 1;
            break;
        } else if (supattr->t == RAD_Attr_Vendor_Specific && attr->t == RAD_Attr_Vendor_Specific &&
                   memcmp(supattr->v, attr->v, 4) == 0) {
            if (!attrvalidate(attr->v + 4, attr->l - 4)) {
                debug(DBG_INFO, "dorewritesup: vendor attribute validation failed, no rewrite");
                return 0;
            }
            vendortype = (uint8_t *)supattr->v + 4;
            for (v = attr->v + 4; v < attr->v + attr->l; v += *(v + 1)) {
                if (*v == *vendortype) {
                    exist = 1;
                    break;
                }
            }
            if (exist)
                break;
        }
    }
    if (!exist) {
        supattr = copytlv(supattr);
        if (!supattr)
            return 0;
        if (!radmsg_add(msg, supattr, 0)) {
            freetlv(supattr);
            return 0;
        }
    }
    return 1;
}

int dorewritesup(struct radmsg *msg, struct list *supattrs) {
    struct list_node *n;
    for (n = list_first(supattrs); n; n = list_next(n)) {
        if (!dorewritesupattr(msg, (struct tlv *)n->data))
            return 0;
    }
    return 1;
}

int dorewrite(struct radmsg *msg, struct rewrite *rewrite) {
    int rv = 1; /* Success.  */

    if (rewrite) {
        if (rewrite->removeattrs || rewrite->removevendorattrs)
            dorewriterm(msg, rewrite->removeattrs, rewrite->removevendorattrs, rewrite->whitelist_mode);
        if (rewrite->modattrs || rewrite->modvattrs)
            if (!dorewritemod(msg, rewrite->modattrs, rewrite->modvattrs))
                rv = 0;
        if (rewrite->supattrs)
            if (!dorewritesup(msg, rewrite->supattrs))
                rv = 0;
        if (rewrite->addattrs)
            if (!dorewriteadd(msg, rewrite->addattrs))
                rv = 0;
    }
    return rv;
}

/** Ad vendor attribute with VENDOR + ATTR and push it on MSG.  ATTR
 * is consumed.  */
int addvendorattr(struct radmsg *msg, uint32_t vendor, struct tlv *attr) {
    struct tlv *vattr;

    vattr = makevendortlv(vendor, attr);
    if (!vattr) {
        freetlv(attr);
        return 0;
    }
    if (!radmsg_add(msg, vattr, 0)) {
        freetlv(vattr);
        return 0;
    }
    return 1;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
