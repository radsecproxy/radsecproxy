/* Copyright (c) 2026, Nova Labs */
/* See LICENSE for licensing information. */

#include "../coa.h"
#include "../debug.h"
#include "../hostport.h"
#include "../list.h"
#include "../radmsg.h"
#include "../radsecproxy.h"
#include "../util.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* internal to radsecproxy.c, needed to exercise the real regex-construction
   path for a plain realm name */
extern struct realm *addrealm(struct list *realmlist, char *value, char **servers,
                              char **accservers, char **coaservers, char *message,
                              uint8_t accresp, uint8_t acclog);

int numtests = 0;

static void ok(int cond, const char *descr) {
    if (!cond)
        printf("not ");
    printf("ok %d - %s\n", ++numtests, descr);
}

static struct radmsg *build_operator_name_msg(const char *const *values, int count) {
    struct radmsg *msg = radmsg_init(RAD_CoA_Request, 7, NULL);
    int i;

    for (i = 0; i < count; i++)
        radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, (uint8_t)strlen(values[i]), (void *)values[i]), 0);
    return msg;
}

/* ---- group A: extract_operator_realm ---- */

static void test_extract_operator_realm(void) {
    char buf[256];

    {
        struct radmsg *msg = radmsg_init(RAD_CoA_Request, 1, NULL);
        ok(extract_operator_realm(msg, buf, sizeof(buf)) == NULL, "no Operator-Name attribute -> NULL");
        radmsg_free(msg);
    }

    {
        const char *values[] = {"0visited.example"};
        struct radmsg *msg = build_operator_name_msg(values, 1);
        ok(extract_operator_realm(msg, buf, sizeof(buf)) == NULL, "Operator-Name with wrong namespace byte -> NULL");
        radmsg_free(msg);
    }

    {
        const char *values[] = {"1visited.example"};
        struct radmsg *msg = build_operator_name_msg(values, 1);
        char *realm = extract_operator_realm(msg, buf, sizeof(buf));
        ok(realm && !strcmp(realm, "visited.example"), "namespace '1' Operator-Name extracts the realm");
        radmsg_free(msg);
    }

    {
        /* extraction must skip the non-'1' first instance */
        const char *values[] = {"0some-other-format", "1second.example"};
        struct radmsg *msg = build_operator_name_msg(values, 2);
        char *realm = extract_operator_realm(msg, buf, sizeof(buf));
        ok(realm && !strcmp(realm, "second.example"), "extraction skips non-'1' variants to find the realm one");
        radmsg_free(msg);
    }

    {
        const char *values[] = {"1truncate.example"};
        struct radmsg *msg = build_operator_name_msg(values, 1);
        char smallbuf[6];
        char *realm = extract_operator_realm(msg, smallbuf, sizeof(smallbuf));
        ok(realm && !strcmp(realm, "trunc"), "extraction truncates to the given buffer size");
        radmsg_free(msg);
    }
}

/* ---- group B: make_error_cause_tlv byte order ---- */

static void test_error_cause_byte_order(void) {
    struct tlv *attr = make_error_cause_tlv(RAD_Err_Request_Not_Routable);
    ok(attr && attr->l == 4, "Error-Cause TLV is 4 bytes");
    ok(attr && attr->v[0] == 0x00 && attr->v[1] == 0x00 && attr->v[2] == 0x01 && attr->v[3] == 0xf6,
       "Error-Cause 502 encoded in network byte order (00 00 01 f6)");
    freetlv(attr);

    attr = make_error_cause_tlv(RAD_Err_NAS_Identification_Mismatch);
    ok(attr && attr->v[0] == 0x00 && attr->v[1] == 0x00 && attr->v[2] == 0x01 && attr->v[3] == 0x93,
       "Error-Cause 403 encoded in network byte order (00 00 01 93)");
    freetlv(attr);
}

/* ---- group C: coa_nak_code ---- */

static void test_coa_nak_code(void) {
    ok(coa_nak_code(RAD_Disconnect_Request) == RAD_Disconnect_NAK, "Disconnect-Request pairs with Disconnect-NAK");
    ok(coa_nak_code(RAD_CoA_Request) == RAD_CoA_NAK, "CoA-Request pairs with CoA-NAK");
}

/* ---- group D: event_timestamp_fresh ---- */

static void test_event_timestamp_fresh(void) {
    uint32_t now = (uint32_t)time(NULL);
    uint32_t stale = now - 3600;
    struct tlv *fresh_attr = maketlv(RAD_Attr_Event_Timestamp, 4, &now);
    struct tlv *stale_attr = maketlv(RAD_Attr_Event_Timestamp, 4, &stale);
    struct tlv *short_attr = maketlv(RAD_Attr_Event_Timestamp, 2, &now);

    uint32_t now_be = htonl(now);
    uint32_t stale_be = htonl(stale);
    memcpy(fresh_attr->v, &now_be, 4);
    memcpy(stale_attr->v, &stale_be, 4);

    ok(event_timestamp_fresh(fresh_attr, 10) == 1, "current Event-Timestamp is fresh");
    ok(event_timestamp_fresh(stale_attr, 10) == 0, "1h-old Event-Timestamp is stale under a 10s window");
    ok(event_timestamp_fresh(NULL, 10) == 1, "absent attribute defaults to fresh (callers pass radmsg_gettype() straight in)");
    ok(event_timestamp_fresh(short_attr, 10) == 1, "malformed-length attribute defaults to fresh");

    freetlv(fresh_attr);
    freetlv(stale_attr);
    freetlv(short_attr);
}

/* ---- shared helpers for findcoaserver tests ---- */

static struct clsrvconf *make_coaserver(const char *name, const char *nasid, const char *host) {
    struct clsrvconf *conf = calloc(1, sizeof(struct clsrvconf));
    struct server *srv;

    conf->name = stringcopy(name, 0);
    if (nasid)
        conf->nas_identifier = stringcopy(nasid, 0);
    conf->hostports = list_create();
    if (host) {
        list_push(conf->hostports, newhostport((char *)host, "3799", 1));
        resolvehostports(conf->hostports, AF_UNSPEC, SOCK_DGRAM);
    }
    conf->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(conf->lock, NULL);

    /* fake an already-connected server so findcoaserver() never calls the real
       addserver() (which would open sockets and spawn threads) */
    srv = calloc(1, sizeof(struct server));
    srv->conf = conf;
    srv->state = RSP_SERVER_STATE_CONNECTED;
    pthread_mutex_init(&srv->lock, NULL);
    conf->servers = srv;

    return conf;
}

static struct realm *make_test_realm(const char *exactname, struct list *coasrvconfs) {
    struct realm *r = calloc(1, sizeof(struct realm));
    char pattern[300];

    r->name = stringcopy(exactname, 0);
    r->refcount = 1000;
    pthread_mutex_init(&r->mutex, NULL);
    pthread_mutex_init(&r->refmutex, NULL);
    snprintf(pattern, sizeof(pattern), "@%s$", exactname);
    regcomp(&r->regex, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    r->coasrvconfs = coasrvconfs;
    return r;
}

static struct radmsg *build_coa_msg(const char *operatorname, const char *username,
                                    const char *nasidentifier, const char *nasip) {
    struct radmsg *msg = radmsg_init(RAD_CoA_Request, 9, NULL);

    if (operatorname)
        radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, (uint8_t)strlen(operatorname), (void *)operatorname), 0);
    if (username)
        radmsg_add(msg, maketlv(RAD_Attr_User_Name, (uint8_t)strlen(username), (void *)username), 0);
    if (nasidentifier)
        radmsg_add(msg, maketlv(RAD_Attr_NAS_Identifier, (uint8_t)strlen(nasidentifier), (void *)nasidentifier), 0);
    if (nasip) {
        struct in_addr addr;
        inet_pton(AF_INET, nasip, &addr);
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, &addr), 0);
    }
    return msg;
}

static struct tlv *make_operator_nas_id_attr(const char *nasid) {
    size_t idlen = strlen(nasid);
    uint8_t *value = malloc(1 + idlen);
    struct tlv *attr;

    value[0] = RAD_Extended_Operator_NAS_Id;
    memcpy(value + 1, nasid, idlen);
    attr = maketlv(RAD_Attr_Extended_Type_1, (uint8_t)(1 + idlen), value);
    free(value);
    return attr;
}

/* ---- group E: findcoaserver - realm + nas-identity routing (nas-discriminating realm) ---- */

static void test_findcoaserver(void) {
    struct clsrvconf *nasa = make_coaserver("nas-a", "nas-a-id", "192.0.2.10");
    struct clsrvconf *nasb = make_coaserver("nas-b", "nas-b-id", "192.0.2.20");
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    struct realm *realm, *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg;

    list_push(coasrvconfs, nasa);
    list_push(coasrvconfs, nasb);
    realm = make_test_realm("visited\\.example", coasrvconfs);
    list_push(reallist, realm);

    /* E1: NAS-Identifier selects nas-b within the matched realm */
    msg = build_coa_msg("1visited.example", "user@example.com", "nas-b-id", NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == realm, "E1: realm found via operator-name");
    ok(server == nasb->servers, "E1: NAS-Identifier=nas-b-id routes to nas-b");
    ok(nasmismatch == 0, "E1: no NAS mismatch reported on a hit");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);

    /* E2: nas-discriminating realm (both coaServers have NASidentifier), NAS-
       Identifier present but matches nothing -> 403 */
    msg = build_coa_msg("1visited.example", NULL, "unknown-nas-id", NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == realm, "E2: realm still found");
    ok(server == NULL, "E2: unmatched NAS-Identifier yields no server");
    ok(nasmismatch == 1, "E2: NAS mismatch flagged for 403 in a nas-discriminating realm");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);

    /* E3: no NAS-identity attributes at all -> first healthy (nas-a, list order) */
    msg = build_coa_msg("1visited.example", NULL, NULL, NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(server == nasa->servers, "E3: no NAS attrs falls back to first healthy coaServer");
    ok(nasmismatch == 0, "E3: no mismatch on plain failover pick");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);

    /* E4: User-Name alone (no Operator-Name) must not route */
    msg = build_coa_msg(NULL, "user@visited.example", NULL, NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == NULL, "E4: User-Name is never used as a routing key");
    ok(server == NULL, "E4: no server without a realm");
    radmsg_free(msg);

    /* E5: Operator-Name realm unknown to us */
    msg = build_coa_msg("1nowhere.example", NULL, NULL, NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == NULL, "E5: unknown operator-name realm -> no realm found");
    ok(server == NULL, "E5: no server for an unknown realm");
    radmsg_free(msg);

    /* E6: NAS-IP-Address matches nas-b's Host address */
    msg = build_coa_msg("1visited.example", NULL, NULL, "192.0.2.20");
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(server == nasb->servers, "E6: NAS-IP-Address selects the coaServer with the matching Host");
    ok(nasmismatch == 0, "E6: no mismatch on an IP-address hit");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group F: empty coaServer list - always 502, nas attrs or not ---- */

static void test_findcoaserver_empty_realm(void) {
    struct list *empty = list_create();
    struct list *reallist = list_create();
    struct realm *realm = make_test_realm("auth-only\\.example", empty);
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg;

    list_push(reallist, realm);

    msg = build_coa_msg("1auth-only.example", NULL, NULL, NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == realm, "F1: realm with no coaServer is still found");
    ok(server == NULL, "F1: empty coaServer list yields no server (502, not 403)");
    ok(nasmismatch == 0, "F1: empty coaServer list is not a NAS mismatch");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);

    /* same, but with a nas identification attribute present - an empty
       coaServer list is ALWAYS 502, regardless of nas attrs */
    msg = build_coa_msg("1auth-only.example", NULL, "some-nas-id", NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == realm, "F2: realm with no coaServer is still found (with nas attrs present)");
    ok(server == NULL, "F2: empty coaServer list yields no server even with nas attrs");
    ok(nasmismatch == 0, "F2: still not a NAS mismatch - 502, not 403");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group G: addrealm() plain-name routing ---- */

static void test_addrealm_plain_name_routing(void) {
    struct clsrvconf *nasx = make_coaserver("nas-x", NULL, NULL);
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    char realmname[] = "plain.example";
    struct realm *added;
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg;

    list_push(coasrvconfs, nasx);

    added = addrealm(reallist, realmname, NULL, NULL, NULL, NULL, 0, 0);
    ok(added != NULL, "G1: addrealm() builds a realm from a plain name");
    if (!added)
        return;
    added->coasrvconfs = coasrvconfs;

    msg = build_coa_msg("1plain.example", NULL, NULL, NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == added, "G2: findcoaserver matches a plain-named realm block");
    ok(server == nasx->servers, "G3: routes to the plain-named realm's coaServer");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group H: Operator-NAS-Identifier first-instance-only ---- */

static void test_operator_nas_id_first_instance_only(void) {
    struct clsrvconf *nasx = make_coaserver("nas-x", "second-id", NULL);
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    struct realm *realm;
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg = radmsg_init(RAD_CoA_Request, 5, NULL);

    list_push(coasrvconfs, nasx);
    realm = make_test_realm("dup241\\.example", coasrvconfs);
    list_push(reallist, realm);

    radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, (uint8_t)strlen("1dup241.example"), (void *)"1dup241.example"), 0);
    radmsg_add(msg, make_operator_nas_id_attr("first-id"), 0);
    radmsg_add(msg, make_operator_nas_id_attr("second-id"), 0);

    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(server == NULL, "H1: only the first 241/8 instance is consulted");
    ok(nasmismatch == 1, "H2: the (would-be-matching) second instance is ignored, yielding a mismatch");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group I: mid-chain (non-nas-discriminating) realm - nas attrs never 403 ---- */

static void test_midchain_realm_nas_attrs_no_403(void) {
    struct clsrvconf *hop1 = make_coaserver("hop-1", NULL, NULL);
    struct clsrvconf *hop2 = make_coaserver("hop-2", NULL, NULL);
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    struct realm *realm;
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg;

    list_push(coasrvconfs, hop1);
    list_push(coasrvconfs, hop2);
    realm = make_test_realm("midchain\\.example", coasrvconfs);
    list_push(reallist, realm);

    msg = build_coa_msg("1midchain.example", NULL, "some-downstream-nas-id", NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(server == hop1->servers, "I1: mid-chain realm falls back to first healthy coaServer despite nas attrs");
    ok(nasmismatch == 0, "I2: no 403 in a non-nas-discriminating realm");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group J: health preference among nas-identity matches ---- */

static void test_nas_match_prefers_healthy(void) {
    struct clsrvconf *failing = make_coaserver("failing-nas", "shared-id", NULL);
    struct clsrvconf *healthy = make_coaserver("healthy-nas", "shared-id", NULL);
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    struct realm *realm;
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg;

    failing->servers->state = RSP_SERVER_STATE_FAILING;

    list_push(coasrvconfs, failing);
    list_push(coasrvconfs, healthy);
    realm = make_test_realm("preferhealthy\\.example", coasrvconfs);
    list_push(reallist, realm);

    msg = build_coa_msg("1preferhealthy.example", NULL, "shared-id", NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(server == healthy->servers, "J1: among nas-identity matches, a FAILING one is skipped for a healthy one");
    ok(nasmismatch == 0, "J2: no mismatch when a healthy match exists");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group K: dynamic subrealm must not shadow the static realm's coaServer ---- */

static void test_dynamic_subrealm_does_not_shadow_static_coaserver(void) {
    struct clsrvconf *nasx = make_coaserver("nas-parent", NULL, NULL);
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    struct realm *parent = calloc(1, sizeof(struct realm));
    struct realm *subrealm = calloc(1, sizeof(struct realm));
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg;

    list_push(coasrvconfs, nasx);

    parent->name = stringcopy("wildcard-parent", 0);
    parent->refcount = 1000;
    pthread_mutex_init(&parent->mutex, NULL);
    pthread_mutex_init(&parent->refmutex, NULL);
    regcomp(&parent->regex, ".*", REG_EXTENDED | REG_ICASE | REG_NOSUB);
    parent->coasrvconfs = coasrvconfs;

    subrealm->name = stringcopy("sub.example.com", 0);
    subrealm->refcount = 1000;
    pthread_mutex_init(&subrealm->mutex, NULL);
    pthread_mutex_init(&subrealm->refmutex, NULL);
    regcomp(&subrealm->regex, "@sub\\.example\\.com$", REG_EXTENDED | REG_ICASE | REG_NOSUB);
    subrealm->parent = parent;

    parent->subrealms = list_create();
    list_push(parent->subrealms, subrealm);
    list_push(reallist, parent);

    msg = build_coa_msg("1sub.example.com", NULL, NULL, NULL);
    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(found == parent, "K1: coa routing resolves the static parent, never a dynamic subrealm");
    ok(server == nasx->servers, "K2: parent's coaServer is used despite an overlapping subrealm");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group M: a malformed identity attribute is treated as absent, not a mismatch ---- */

static void test_malformed_nas_ip_treated_as_absent(void) {
    struct clsrvconf *nasa = make_coaserver("nas-a", "nas-a-id", NULL);
    struct clsrvconf *nasb = make_coaserver("nas-b", "nas-b-id", NULL);
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    struct realm *realm;
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg = radmsg_init(RAD_CoA_Request, 5, NULL);
    uint8_t badip[3] = {192, 0, 2};

    list_push(coasrvconfs, nasa);
    list_push(coasrvconfs, nasb);
    realm = make_test_realm("malformed\\.example", coasrvconfs);
    list_push(reallist, realm);

    radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, (uint8_t)strlen("1malformed.example"), (void *)"1malformed.example"), 0);
    radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, sizeof(badip), badip), 0);

    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(server == nasa->servers, "M1: malformed NAS-IP-Address (l != 4) is treated as absent, falls back to failover");
    ok(nasmismatch == 0, "M2: no mismatch - a nas-discriminating realm does not 403 on a malformed attribute");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

static void test_empty_nas_identifier_treated_as_absent(void) {
    struct clsrvconf *nasa = make_coaserver("nas-a", "nas-a-id", NULL);
    struct clsrvconf *nasb = make_coaserver("nas-b", "nas-b-id", NULL);
    struct list *coasrvconfs = list_create();
    struct list *reallist = list_create();
    struct realm *realm;
    struct realm *found;
    struct server *server;
    int nasmismatch;
    struct radmsg *msg = radmsg_init(RAD_CoA_Request, 5, NULL);

    list_push(coasrvconfs, nasa);
    list_push(coasrvconfs, nasb);
    realm = make_test_realm("emptynasid\\.example", coasrvconfs);
    list_push(reallist, realm);

    radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, (uint8_t)strlen("1emptynasid.example"), (void *)"1emptynasid.example"), 0);
    radmsg_add(msg, maketlv(RAD_Attr_NAS_Identifier, 0, NULL), 0);

    server = findcoaserver(reallist, &found, msg, &nasmismatch);
    ok(server == nasa->servers, "M3: empty NAS-Identifier (l == 0) is treated as absent, falls back to failover");
    ok(nasmismatch == 0, "M4: no mismatch - a nas-discriminating realm does not 403 on a malformed attribute");
    if (found)
        pthread_mutex_unlock(&found->mutex);
    radmsg_free(msg);
}

/* ---- group L: message-authenticator / request-authenticator wire format for codes 40-45 ---- */

static void hmac_md5(const uint8_t *secret, int secretlen, const uint8_t *data, int datalen, uint8_t *out) {
    HMAC(EVP_md5(), secret, secretlen, data, datalen, out, NULL);
}

static void compute_auth(const uint8_t *buf, int len, const uint8_t *auth16, const char *secret, uint8_t *out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestInit(mdctx, EVP_md5());
    EVP_DigestUpdate(mdctx, buf, 4);
    EVP_DigestUpdate(mdctx, auth16, 16);
    EVP_DigestUpdate(mdctx, buf + 20, len - 20);
    EVP_DigestUpdate(mdctx, secret, strlen(secret));
    EVP_DigestFinal(mdctx, out, NULL);
    EVP_MD_CTX_free(mdctx);
}

static int build_coa_request_wire(uint8_t *buf, const char *secret, int corrupt_ma) {
    static const uint8_t username[] = "user@example.com";
    int userlen = (int)strlen((char *)username);
    int attrlen = 2 + userlen + 18;
    int length = 20 + attrlen;
    uint8_t zero16[16] = {0};
    uint8_t ma[16];
    int secretlen = (int)strlen(secret);

    buf[0] = RAD_CoA_Request;
    buf[1] = 9;
    buf[2] = (uint8_t)(length >> 8);
    buf[3] = (uint8_t)length;
    memset(buf + 4, 0, 16);

    buf[20] = RAD_Attr_User_Name;
    buf[21] = (uint8_t)(2 + userlen);
    memcpy(buf + 22, username, userlen);

    buf[22 + userlen] = RAD_Attr_Message_Authenticator;
    buf[23 + userlen] = 18;
    memset(buf + 24 + userlen, 0, 16);

    hmac_md5((const uint8_t *)secret, secretlen, buf, length, ma);
    if (corrupt_ma)
        ma[0] ^= 0xff;
    memcpy(buf + 24 + userlen, ma, 16);

    {
        uint8_t reqauth[16];
        compute_auth(buf, length, zero16, secret, reqauth);
        memcpy(buf + 4, reqauth, 16);
    }

    return length;
}

static void test_ma_and_auth_codes_40_45(void) {
    uint8_t buf[256];
    const char *secret = "testing123456";
    int len;
    struct radmsg *msg;

    len = build_coa_request_wire(buf, secret, 0);
    msg = buf2radmsg(buf, len, (uint8_t *)secret, (int)strlen(secret), NULL);
    ok(msg != NULL, "L1: well-formed CoA-Request parses");
    ok(msg && msg->code == RAD_CoA_Request, "L2: parsed code is CoA-Request");
    ok(msg && !msg->msgauthinvalid, "L3: correctly-computed Message-Authenticator validates");
    radmsg_free(msg);

    len = build_coa_request_wire(buf, secret, 1);
    msg = buf2radmsg(buf, len, (uint8_t *)secret, (int)strlen(secret), NULL);
    ok(msg && msg->msgauthinvalid, "L4: corrupted Message-Authenticator is flagged invalid");
    radmsg_free(msg);

    /* L5-L7: egress signing must match an independent recomputation and be
       copied back into msg->auth */
    {
        struct radmsg *out = radmsg_init(RAD_CoA_Request, 3, NULL);
        uint8_t *outbuf = NULL;
        int outlen;
        uint8_t expected[16];
        uint8_t zero16[16] = {0};
        static const char username[] = "user@example.com";

        memset(out->auth, 0, 16);
        radmsg_add(out, maketlv(RAD_Attr_User_Name, (uint8_t)strlen(username), (void *)username), 0);

        outlen = radmsg2buf(out, (uint8_t *)secret, (int)strlen(secret), &outbuf);
        ok(outlen > 0 && outbuf != NULL, "L5: radmsg2buf encodes a CoA-Request");

        compute_auth(outbuf, outlen, zero16, secret, expected);
        ok(outbuf && !memcmp(outbuf + 4, expected, 16), "L6: acct-style request authenticator matches independent computation");
        ok(!memcmp(out->auth, expected, 16), "L7: radmsg2buf copies the computed request authenticator back into msg->auth");

        free(outbuf);
        radmsg_free(out);
    }

    /* L8-L9: egress signing of a CoA-NAK - Response Authenticator computed
       over the correlated request's authenticator (not zeroed) */
    {
        uint8_t requestauth[16];
        struct radmsg *nak;
        uint8_t *outbuf = NULL;
        int outlen;
        uint8_t expected[16];
        struct tlv *errorcause;

        memset(requestauth, 0x42, 16);
        nak = radmsg_init(RAD_CoA_NAK, 3, requestauth);
        errorcause = make_error_cause_tlv(RAD_Err_Request_Not_Routable);
        radmsg_add(nak, errorcause, 0);

        outlen = radmsg2buf(nak, (uint8_t *)secret, (int)strlen(secret), &outbuf);
        ok(outlen > 0 && outbuf != NULL, "L8: radmsg2buf encodes a CoA-NAK");

        compute_auth(outbuf, outlen, requestauth, secret, expected);
        ok(outbuf && !memcmp(outbuf + 4, expected, 16), "L9: Response Authenticator computed over the original request authenticator");

        free(outbuf);
        radmsg_free(nak);
    }
}

int main(void) {
    debug_init("t_coa");

    test_extract_operator_realm();
    test_error_cause_byte_order();
    test_coa_nak_code();
    test_event_timestamp_fresh();
    test_findcoaserver();
    test_findcoaserver_empty_realm();
    test_addrealm_plain_name_routing();
    test_operator_nas_id_first_instance_only();
    test_midchain_realm_nas_attrs_no_403();
    test_nas_match_prefers_healthy();
    test_dynamic_subrealm_does_not_shadow_static_coaserver();
    test_malformed_nas_ip_treated_as_absent();
    test_empty_nas_identifier_treated_as_absent();
    test_ma_and_auth_codes_40_45();

    printf("1..%d\n", numtests);
    return 0;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
