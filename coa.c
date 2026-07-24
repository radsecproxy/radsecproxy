/* Copyright (c) 2026, Nova Labs */
/* See LICENSE for licensing information. */

#include "coa.h"
#include "debug.h"
#include "hostport.h"
#include "list.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

char *extract_operator_realm(struct radmsg *msg, char *buf, size_t bufsize) {
    struct list *attrs = radmsg_getalltype(msg, RAD_Attr_Operator_Name);
    struct list_node *node;
    char *result = NULL;
    int len;

    if (!attrs)
        return NULL;

    for (node = list_first(attrs); node; node = list_next(node)) {
        struct tlv *attr = node->data;
        if (attr->l > 1 && attr->v[0] == '1') {
            len = attr->l - 1;
            if (len > (int)bufsize - 1)
                len = (int)bufsize - 1;
            memcpy(buf, attr->v + 1, len);
            buf[len] = '\0';
            result = buf;
            break;
        }
    }
    list_free(attrs);
    return result;
}

static struct realm *find_coa_realm(struct list *realmlist, const char *subject) {
    struct list_node *entry;
    struct realm *realm;

    for (entry = list_first(realmlist); entry; entry = list_next(entry)) {
        realm = (struct realm *)entry->data;
        if (!regexec(&realm->regex, subject, 0, NULL, 0)) {
            pthread_mutex_lock(&realm->mutex);
            pthread_mutex_lock(&realm->refmutex);
            realm->refcount++;
            pthread_mutex_unlock(&realm->refmutex);
            return realm;
        }
    }
    return NULL;
}

static struct tlv *first_operator_nas_id(struct radmsg *msg) {
    struct list *extattrs = radmsg_getalltype(msg, RAD_Attr_Extended_Type_1);
    struct list_node *node;
    struct tlv *found = NULL;

    if (!extattrs)
        return NULL;
    for (node = list_first(extattrs); node; node = list_next(node)) {
        struct tlv *attr = node->data;
        if (attr->l > 1 && attr->v[0] == RAD_Extended_Operator_NAS_Id) {
            found = attr;
            break;
        }
    }
    list_free(extattrs);
    return found;
}

struct nas_identity_attrs {
    struct tlv *operator_nas_id;
    struct tlv *nas_identifier;
    struct tlv *nas_ip;
    struct tlv *nas_ipv6;
};

static void resolve_nas_identity_attrs(struct radmsg *msg, struct nas_identity_attrs *attrs) {
    struct tlv *attr;

    attrs->operator_nas_id = first_operator_nas_id(msg);

    attr = radmsg_gettype(msg, RAD_Attr_NAS_Identifier);
    attrs->nas_identifier = (attr && attr->l >= 1) ? attr : NULL;

    attr = radmsg_gettype(msg, RAD_Attr_NAS_IP_Address);
    attrs->nas_ip = (attr && attr->l == 4) ? attr : NULL;

    attr = radmsg_gettype(msg, RAD_Attr_NAS_IPv6_Address);
    attrs->nas_ipv6 = (attr && attr->l == 16) ? attr : NULL;
}

static int has_nas_identity_attrs(const struct nas_identity_attrs *attrs) {
    return attrs->operator_nas_id || attrs->nas_identifier || attrs->nas_ip || attrs->nas_ipv6;
}

static int nas_identifier_equals(const struct clsrvconf *conf, const uint8_t *value, size_t length) {
    size_t idlen;

    if (!conf->nas_identifier)
        return 0;
    idlen = strlen(conf->nas_identifier);
    return length == idlen && !memcmp(value, conf->nas_identifier, idlen);
}

static int match_nas_ipv4(const struct clsrvconf *conf, const struct tlv *attr) {
    struct sockaddr_in nasaddr;

    memset(&nasaddr, 0, sizeof(nasaddr));
    nasaddr.sin_family = AF_INET;
    memcpy(&nasaddr.sin_addr, attr->v, 4);
    return addressmatches(conf->hostports, (struct sockaddr *)&nasaddr, 0, NULL);
}

static int match_nas_ipv6(const struct clsrvconf *conf, const struct tlv *attr) {
    struct sockaddr_in6 nasaddr;

    memset(&nasaddr, 0, sizeof(nasaddr));
    nasaddr.sin6_family = AF_INET6;
    memcpy(&nasaddr.sin6_addr, attr->v, 16);
    return addressmatches(conf->hostports, (struct sockaddr *)&nasaddr, 0, NULL);
}

static int conf_matches_nas_identity(const struct clsrvconf *conf, const struct nas_identity_attrs *attrs) {
    return (attrs->operator_nas_id && nas_identifier_equals(conf, attrs->operator_nas_id->v + 1, attrs->operator_nas_id->l - 1)) ||
           (attrs->nas_identifier && nas_identifier_equals(conf, attrs->nas_identifier->v, attrs->nas_identifier->l)) ||
           (attrs->nas_ip && match_nas_ipv4(conf, attrs->nas_ip)) ||
           (attrs->nas_ipv6 && match_nas_ipv6(conf, attrs->nas_ipv6));
}

static int realm_is_nas_discriminating(struct list *coasrvconfs) {
    struct list_node *entry;

    for (entry = list_first(coasrvconfs); entry; entry = list_next(entry))
        if (((struct clsrvconf *)entry->data)->nas_identifier)
            return 1;
    return 0;
}

struct server *findcoaserver(struct list *realmlist, struct realm **realm, struct radmsg *msg, int *nasmismatch) {
    char realmbuf[256];
    char subjectbuf[258];
    char *realmstr;
    struct nas_identity_attrs idattrs;
    struct clsrvconf *srvconf;

    *nasmismatch = 0;
    *realm = NULL;

    realmstr = extract_operator_realm(msg, realmbuf, sizeof(realmbuf));
    if (!realmstr) {
        debug(DBG_DBG, "findcoaserver: no operator-name realm in request");
        return NULL;
    }

    snprintf(subjectbuf, sizeof(subjectbuf), "@%s", realmstr);
    *realm = find_coa_realm(realmlist, subjectbuf);
    if (!*realm) {
        debug(DBG_DBG, "findcoaserver: no realm matches operator-name %s", realmstr);
        return NULL;
    }
    debug(DBG_DBG, "findcoaserver: found matching realm: %s", (*realm)->name);

    resolve_nas_identity_attrs(msg, &idattrs);

    if (has_nas_identity_attrs(&idattrs)) {
        struct list *matches = list_create();
        struct list_node *entry;

        if (!matches) {
            debug(DBG_ERR, "findcoaserver: malloc failed");
            return NULL;
        }

        for (entry = list_first((*realm)->coasrvconfs); entry; entry = list_next(entry)) {
            struct clsrvconf *conf = (struct clsrvconf *)entry->data;
            if (conf_matches_nas_identity(conf, &idattrs) && !list_push(matches, conf)) {
                debug(DBG_ERR, "findcoaserver: malloc failed");
                list_free(matches);
                return NULL;
            }
        }

        if (list_first(matches)) {
            srvconf = choosesrvconf(matches);
        } else if (realm_is_nas_discriminating((*realm)->coasrvconfs)) {
            debug(DBG_INFO, "findcoaserver: nas identification attributes matched no coaServer in nas-discriminating realm %s", (*realm)->name);
            *nasmismatch = 1;
            list_free(matches);
            return NULL;
        } else {
            srvconf = choosesrvconf((*realm)->coasrvconfs);
        }
        list_free(matches);
    } else {
        srvconf = choosesrvconf((*realm)->coasrvconfs);
    }

    if (!srvconf)
        return NULL;

    if (!srvconf->servers) {
        if (srvconf->dynamiclookupcommand) {
            debug(DBG_INFO, "findcoaserver: dynamic lookup not supported for coaServer %s", srvconf->name);
            return NULL;
        }
        addserver(srvconf, (*realm)->name);
    }

    return srvconf->servers;
}

struct tlv *make_error_cause_tlv(uint32_t cause) {
    uint32_t netcause = htonl(cause);
    return maketlv(RAD_Attr_Error_Cause, sizeof(netcause), &netcause);
}

uint8_t coa_nak_code(uint8_t requestcode) {
    return requestcode == RAD_Disconnect_Request ? RAD_Disconnect_NAK : RAD_CoA_NAK;
}

int event_timestamp_fresh(struct tlv *attr, uint8_t window) {
    uint32_t ts;
    int64_t now;
    int64_t delta;

    if (!attr || attr->l != 4)
        return 1;

    ts = tlv2longint(attr);
    now = time(NULL);
    delta = now - (int64_t)ts;
    if (delta < 0)
        delta = -delta;
    return delta <= (int64_t)window;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
