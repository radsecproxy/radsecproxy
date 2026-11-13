/* Copyright (c) 2026, Nova Labs */
/* Copyright (c) 2026, CyB0rgg */
/* See LICENSE for licensing information. */

#include "../coa.h"
#include "../debug.h"
#include "../hostport.h"
#include "../list.h"
#include "../radmsg.h"
#include "../radmsgcrypto.h"
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

/* not in a header */
extern struct realm *addrealm(struct list *realmlist, char *value, char **servers, char **accservers, char **coaservers, char *message, uint8_t accresp, uint8_t acclog);
extern void freerealm(struct realm *realm);

int numtests = 0;

static struct list *realms;
static struct realm *found;
static int mismatch;

void test_ok(int condition, char *msg) {
    if (!condition)
        printf("not ");
    printf("ok %d - %s\n", ++numtests, msg);
}

void test_eq(int expected, int actual, char *msg) {
    if (actual != expected)
        printf("not ");
    printf("ok %d - %s (expected %d, got %d)\n", ++numtests, msg, expected, actual);
}

/* a CoA-Request with the attributes given */
static struct radmsg *coamsg(char *opname, char *nasid, char *nasip) {
    struct radmsg *msg = radmsg_init(RAD_CoA_Request, 9, NULL);
    struct in_addr addr;

    if (opname)
        radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, strlen(opname), opname), 0);
    if (nasid)
        radmsg_add(msg, maketlv(RAD_Attr_NAS_Identifier, strlen(nasid), nasid), 0);
    if (nasip) {
        inet_pton(AF_INET, nasip, &addr);
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, &addr), 0);
    }
    return msg;
}

/* a coaServer block, pretend connected so addserver() is not called */
static struct clsrvconf *coaserver(char *name, char *nasid, char *host) {
    struct clsrvconf *conf = calloc(1, sizeof(struct clsrvconf));
    struct server *server = calloc(1, sizeof(struct server));

    conf->name = name;
    conf->nas_identifier = nasid;
    conf->hostports = list_create();
    if (host) {
        list_push(conf->hostports, newhostport(host, "3799", 1));
        resolvehostports(conf->hostports, AF_UNSPEC, SOCK_DGRAM);
    }
    conf->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(conf->lock, NULL);
    server->conf = conf;
    server->state = RSP_SERVER_STATE_CONNECTED;
    pthread_mutex_init(&server->lock, NULL);
    conf->servers = server;
    return conf;
}

static void freecoaserver(struct clsrvconf *conf) {
    pthread_mutex_destroy(&conf->servers->lock);
    free(conf->servers);
    pthread_mutex_destroy(conf->lock);
    free(conf->lock);
    freehostports(conf->hostports);
    free(conf);
}

/* a realm matching regex with up to two coaServers, on the realm list */
static struct realm *testrealm(char *regex, struct clsrvconf *a, struct clsrvconf *b) {
    struct realm *realm = calloc(1, sizeof(struct realm));

    realm->name = stringcopy(regex, 0);
    realm->refcount = 1;
    pthread_mutex_init(&realm->mutex, NULL);
    pthread_mutex_init(&realm->refmutex, NULL);
    regcomp(&realm->regex, regex, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    realm->coasrvconfs = list_create();
    if (a)
        list_push(realm->coasrvconfs, a);
    if (b)
        list_push(realm->coasrvconfs, b);
    list_push(realms, realm);
    return realm;
}

/* the coaServers are freed by their makers */
static void freetestrealm(struct realm *realm) {
    list_removedata(realms, realm);
    while (list_shift(realm->coasrvconfs))
        ;
    freerealm(realm);
}

/* findcoaserver, dropping the realm lock and reference it leaves; frees msg */
static struct server *lookup(struct radmsg *msg) {
    struct server *server = findcoaserver(realms, &found, msg, &mismatch);

    if (found) {
        pthread_mutex_unlock(&found->mutex);
        freerealm(found);
    }
    radmsg_free(msg);
    return server;
}

/* extract_operator_realm */
static void test_extract_operator_realm(void) {
    struct {
        char *first, *second, *expect, *descr;
    } cases[] = {
        {NULL, NULL, NULL, "no operator-name"},
        {"0visited.example", NULL, "0visited.example", "namespace 0 whole value"},
        {"4IRONWIFI:US", NULL, "4IRONWIFI:US", "namespace 4 whole value"},
        {"1", NULL, NULL, "namespace byte only"},
        {"1visited.example", NULL, "visited.example", "namespace 1 realm"},
        {"0some-other-format", "1second.example", "0some-other-format", "first instance wins"},
        {"1", "1second.example", "second.example", "empty instance skipped"},
    };
    char buf[256], small[6];
    struct radmsg *msg;
    char *realm;
    int i;

    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        msg = coamsg(cases[i].first, NULL, NULL);
        if (cases[i].second)
            radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, strlen(cases[i].second), cases[i].second), 0);
        realm = extract_operator_realm(msg, buf, sizeof(buf));
        test_ok(cases[i].expect ? realm && !strcmp(realm, cases[i].expect) : !realm, cases[i].descr);
        radmsg_free(msg);
    }
    msg = coamsg("1truncate.example", NULL, NULL);
    realm = extract_operator_realm(msg, small, sizeof(small));
    test_ok(realm && !strcmp(realm, "trunc"), "truncated to the buffer");
    radmsg_free(msg);
}

/* make_error_cause_tlv, coa_nak_code, event_timestamp_fresh */
static void test_coa_helpers(void) {
    struct tlv *attr = make_error_cause_tlv(RAD_Err_Request_Not_Routable);
    uint32_t now = (uint32_t)time(NULL);
    struct tlv *fresh = maketlvlongint(RAD_Attr_Event_Timestamp, now);
    struct tlv *old = maketlvlongint(RAD_Attr_Event_Timestamp, now - 3600);
    struct tlv *bad = maketlv(RAD_Attr_Event_Timestamp, 2, &now);

    test_ok(attr && attr->l == 4 && !memcmp(attr->v, "\0\0\x01\xf6", 4), "error-cause 502 network order");
    freetlv(attr);
    attr = make_error_cause_tlv(RAD_Err_NAS_Identification_Mismatch);
    test_ok(attr && attr->l == 4 && !memcmp(attr->v, "\0\0\x01\x93", 4), "error-cause 403 network order");
    freetlv(attr);
    test_ok(coa_nak_code(RAD_Disconnect_Request) == RAD_Disconnect_NAK, "disconnect-request pairs disconnect-nak");
    test_ok(coa_nak_code(RAD_CoA_Request) == RAD_CoA_NAK, "coa-request pairs coa-nak");
    test_ok(event_timestamp_fresh(fresh, 10), "current timestamp fresh");
    test_ok(!event_timestamp_fresh(old, 10), "old timestamp stale");
    test_ok(event_timestamp_fresh(NULL, 10), "absent timestamp fresh");
    test_ok(event_timestamp_fresh(bad, 10), "malformed timestamp fresh");
    freetlv(fresh);
    freetlv(old);
    freetlv(bad);
}

/* findcoaserver */
static void test_findcoaserver(void) {
    struct clsrvconf *nasa = coaserver("nas-a", "nas-a-id", "192.0.2.10");
    struct clsrvconf *nasb = coaserver("nas-b", "nas-b-id", "192.0.2.20");
    struct realm *realm = testrealm("@visited\\.example$", nasa, nasb);
    struct server *server;
    struct radmsg *msg;

    server = lookup(coamsg("1visited.example", "nas-b-id", NULL));
    test_ok(found == realm && server == nasb->servers, "nas-identifier selects the nas");
    test_eq(0, mismatch, "no mismatch on a hit");
    server = lookup(coamsg("1visited.example", "unknown-nas-id", NULL));
    test_ok(found == realm && !server, "unknown nas-identifier no server");
    test_eq(1, mismatch, "unknown nas-identifier mismatch");
    server = lookup(coamsg("1visited.example", NULL, NULL));
    test_ok(server == nasa->servers && !mismatch, "no nas attributes first server");
    msg = coamsg(NULL, NULL, NULL);
    radmsg_add(msg, maketlv(RAD_Attr_User_Name, 20, (void *)"user@visited.example"), 0);
    test_ok(!lookup(msg) && !found, "user-name is no routing key");
    test_ok(!lookup(coamsg("1nowhere.example", NULL, NULL)) && !found, "unknown realm");
    server = lookup(coamsg("1visited.example", NULL, "192.0.2.20"));
    test_ok(server == nasb->servers && !mismatch, "nas-ip-address selects the nas");
    freetestrealm(realm);

    /* a realm without coaServer never reports a mismatch */
    realm = testrealm("@auth-only\\.example$", NULL, NULL);
    test_ok(!lookup(coamsg("1auth-only.example", NULL, NULL)) && found == realm && !mismatch, "empty realm no server");
    test_ok(!lookup(coamsg("1auth-only.example", "some-nas-id", NULL)) && !mismatch, "empty realm no mismatch");
    freetestrealm(realm);
    freecoaserver(nasa);
    freecoaserver(nasb);
}

/* nas identity among proxies, among nases */
static void test_findcoaserver_identity(void) {
    struct clsrvconf *hop1 = coaserver("hop-1", NULL, NULL), *hop2 = coaserver("hop-2", NULL, NULL);
    struct clsrvconf *nasa = coaserver("nas-a", "nas-a-id", NULL), *nasb = coaserver("nas-b", "nas-b-id", NULL);
    struct realm *realm = testrealm("@midchain\\.example$", hop1, hop2);
    struct radmsg *msg;
    uint8_t badip[3] = {192, 0, 2};

    test_ok(lookup(coamsg("1midchain.example", "downstream-nas-id", NULL)) == hop1->servers && !mismatch, "proxies ignore nas attributes");
    freetestrealm(realm);

    realm = testrealm("@nases\\.example$", nasa, nasb);
    msg = coamsg("1nases.example", NULL, NULL);
    radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, 8, (void *)"first-id"), 0);
    radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, 8, (void *)"nas-b-id"), 0);
    test_ok(!lookup(msg) && mismatch, "first operator-nas-identifier only");
    msg = coamsg("1nases.example", NULL, NULL);
    radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 3, badip), 0);
    test_ok(lookup(msg) == nasa->servers && !mismatch, "malformed nas-ip-address absent");
    msg = coamsg("1nases.example", NULL, NULL);
    radmsg_add(msg, maketlv(RAD_Attr_NAS_Identifier, 0, NULL), 0);
    test_ok(lookup(msg) == nasa->servers && !mismatch, "empty nas-identifier absent");
    nasa->servers->state = RSP_SERVER_STATE_FAILING;
    nasb->nas_identifier = "nas-a-id";
    test_ok(lookup(coamsg("1nases.example", "nas-a-id", NULL)) == nasb->servers && !mismatch, "failing nas skipped");
    freetestrealm(realm);
    freecoaserver(hop1);
    freecoaserver(hop2);
    freecoaserver(nasa);
    freecoaserver(nasb);
}

/* a subrealm never shadows the realm; addrealm() builds the regex for a plain name */
static void test_findcoaserver_realms(void) {
    struct clsrvconf *nasx = coaserver("nas-x", NULL, NULL);
    struct realm *parent = testrealm(".*", nasx, NULL);
    struct realm *sub = testrealm("@sub\\.example\\.com$", NULL, NULL), *added;
    char name[] = "plain.example";

    list_removedata(realms, sub);
    sub->parent = parent;
    parent->refcount++; /* the subrealm's reference */
    parent->subrealms = list_create();
    list_push(parent->subrealms, sub);
    test_ok(lookup(coamsg("1sub.example.com", NULL, NULL)) == nasx->servers && found == parent, "parent realm, not the subrealm");
    list_shift(parent->subrealms);
    freetestrealm(sub);
    freetestrealm(parent);

    added = addrealm(realms, name, NULL, NULL, NULL, NULL, 0, 0);
    test_ok(added != NULL, "addrealm plain name");
    if (added) {
        added->coasrvconfs = list_create();
        list_push(added->coasrvconfs, nasx);
        test_ok(lookup(coamsg("1plain.example", NULL, NULL)) == nasx->servers && found == added, "plain name matched");
        freetestrealm(added);
    }
    freecoaserver(nasx);
}

/* md5 over the header, auth16 and the attributes, as rfc 2866 3 */
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

/* a CoA-Request with User-Name and Message-Authenticator on the wire */
static int build_coa_request_wire(uint8_t *buf, const char *secret, int corrupt_ma) {
    static const uint8_t username[] = "user@example.com";
    int userlen = (int)strlen((char *)username);
    int length = 20 + 2 + userlen + 18;
    uint8_t zero16[16] = {0};
    uint8_t ma[16], reqauth[16];

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
    HMAC(EVP_md5(), secret, (int)strlen(secret), buf, length, ma, NULL);
    if (corrupt_ma)
        ma[0] ^= 0xff;
    memcpy(buf + 24 + userlen, ma, 16);
    compute_auth(buf, length, zero16, secret, reqauth);
    memcpy(buf + 4, reqauth, 16);
    return length;
}

/* the message-authenticator requirement is for access-request, not for the coa codes */
static void test_msgauth_required(void) {
    struct clsrvconf conf;
    struct radmsg *access = radmsg_init(RAD_Access_Request, 1, NULL);
    struct radmsg *coa = radmsg_init(RAD_CoA_Request, 2, NULL);
    struct radmsg *disconnect = radmsg_init(RAD_Disconnect_Request, 3, NULL);

    memset(&conf, 0, sizeof(conf));
    conf.type = RAD_UDP;
    test_ok(!msgauthrequired(&conf, access), "nothing required by default");
    conf.reqmsgauth = 1;
    test_ok(msgauthrequired(&conf, access), "access-request on udp required");
    test_ok(!msgauthrequired(&conf, coa), "coa-request not required");
    test_ok(!msgauthrequired(&conf, disconnect), "disconnect-request not required");
    conf.type = RAD_TCP;
    test_ok(msgauthrequired(&conf, access), "access-request on tcp required");
    test_ok(!msgauthrequired(&conf, coa), "coa-request on tcp not required");
    conf.type = RAD_TLS;
    test_ok(!msgauthrequired(&conf, access), "ignored on tls");
    conf.type = RAD_UDP;
    conf.reqmsgauth = 0;
    conf.reqmsgauthproxy = 1;
    test_ok(!msgauthrequired(&conf, access), "proxy flag without proxy-state not required");
    radmsg_add(access, maketlv(RAD_Attr_Proxy_State, 4, (void *)"abcd"), 0);
    test_ok(msgauthrequired(&conf, access), "proxy flag with proxy-state required");
    radmsg_add(coa, maketlv(RAD_Attr_Proxy_State, 4, (void *)"abcd"), 0);
    test_ok(!msgauthrequired(&conf, coa), "coa-request with proxy-state not required");
    radmsg_free(access);
    radmsg_free(coa);
    radmsg_free(disconnect);
}

/* tunnel-password in a coa or disconnect request is obfuscated with a zero vector in place of
   the request authenticator, before and after it is reencrypted for the next hop */
static void test_recrypt_tunnel_password(void) {
    struct {
        uint8_t code;
        char *recrypted, *readable;
    } cases[] = {
        {RAD_CoA_Request, "coa-request tunnel-password reencrypted", "coa-request tunnel-password readable at the next hop"},
        {RAD_Disconnect_Request, "disconnect-request tunnel-password reencrypted", "disconnect-request tunnel-password readable at the next hop"},
    };
    struct clsrvconf from, to;
    uint8_t zero16[16] = {0}, plain[16], value[3 + 16];
    struct radmsg *msg;
    struct tlv *attr;
    size_t i;

    memset(&from, 0, sizeof(from));
    memset(&to, 0, sizeof(to));
    from.secret = (uint8_t *)"server-secret";
    from.secret_len = 13;
    to.secret = (uint8_t *)"nas-secret";
    to.secret_len = 10;
    memset(plain, 0, sizeof(plain));
    plain[0] = 8;
    memcpy(plain + 1, "password", 8);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        value[0] = 0;
        value[1] = 0x80;
        value[2] = 0x01;
        memcpy(value + 3, plain, sizeof(plain));
        pwdcrypt(1, value + 3, sizeof(plain), from.secret, from.secret_len, zero16, value + 1, 2);
        msg = radmsg_init(cases[i].code, 1, NULL);
        /* the request authenticator received, an md5 over the packet */
        memset(msg->auth, 0x42, 16);
        radmsg_add(msg, maketlv(RAD_Attr_Tunnel_Password, sizeof(value), value), 0);
        test_eq(1, recryptrequestattrs(msg, &from, &to, msg->auth), cases[i].recrypted);
        attr = radmsg_gettype(msg, RAD_Attr_Tunnel_Password);
        test_ok(attr && attr->l == sizeof(value) &&
                    pwdcrypt(0, attr->v + 3, sizeof(plain), to.secret, to.secret_len, zero16, attr->v + 1, 2) &&
                    !memcmp(attr->v + 3, plain, sizeof(plain)),
                cases[i].readable);
        radmsg_free(msg);
    }
}

/* message-authenticator and request-authenticator for the coa codes */
static void test_wire_format(void) {
    const char *secret = "testing123456";
    uint8_t buf[256], expected[16], requestauth[16], zero16[16] = {0};
    uint8_t *outbuf = NULL;
    struct radmsg *msg;
    int len;

    len = build_coa_request_wire(buf, secret, 0);
    msg = buf2radmsg(buf, len, (uint8_t *)secret, (int)strlen(secret), NULL);
    test_ok(msg && msg->code == RAD_CoA_Request, "coa-request parses");
    test_ok(msg && msg->authstate == RSP_RADMSG_MSGAUTH_VALID, "message-authenticator validates");
    radmsg_free(msg);
    len = build_coa_request_wire(buf, secret, 1);
    msg = buf2radmsg(buf, len, (uint8_t *)secret, (int)strlen(secret), NULL);
    test_ok(msg && (msg->authstate == RSP_RADMSG_MSGAUTH_INVALID || msg->authstate == RSP_RADMSG_INVALID), "corrupted message-authenticator invalid");
    radmsg_free(msg);

    msg = radmsg_init(RAD_CoA_Request, 3, NULL);
    memset(msg->auth, 0, 16);
    radmsg_add(msg, maketlv(RAD_Attr_User_Name, 16, (void *)"user@example.com"), 0);
    len = radmsg2buf(msg, (uint8_t *)secret, (int)strlen(secret), &outbuf);
    test_ok(len > 0 && outbuf != NULL, "coa-request encodes");
    compute_auth(outbuf, len, zero16, secret, expected);
    test_ok(outbuf && !memcmp(outbuf + 4, expected, 16), "request authenticator as accounting");
    test_ok(!memcmp(msg->auth, expected, 16), "request authenticator copied back");
    free(outbuf);
    radmsg_free(msg);

    memset(requestauth, 0x42, 16);
    msg = radmsg_init(RAD_CoA_NAK, 3, requestauth);
    radmsg_add(msg, make_error_cause_tlv(RAD_Err_Request_Not_Routable), 0);
    outbuf = NULL;
    len = radmsg2buf(msg, (uint8_t *)secret, (int)strlen(secret), &outbuf);
    test_ok(len > 0 && outbuf != NULL, "coa-nak encodes");
    compute_auth(outbuf, len, requestauth, secret, expected);
    test_ok(outbuf && !memcmp(outbuf + 4, expected, 16), "response authenticator over the request authenticator");
    free(outbuf);
    radmsg_free(msg);
}

int main(int argc, char *argv[]) {
    debug_init("t_coa");
    realms = list_create();

    test_extract_operator_realm();
    test_coa_helpers();
    test_findcoaserver();
    test_findcoaserver_identity();
    test_findcoaserver_realms();
    test_msgauth_required();
    test_recrypt_tunnel_password();
    test_wire_format();

    list_free(realms);
    printf("1..%d\n", numtests);
    return 0;
}
