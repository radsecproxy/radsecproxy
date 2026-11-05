/* Copyright (c) 2026, Nova Labs */
/* Copyright (c) 2026, CyB0rgg */
/* See LICENSE for licensing information. */

#include "../coa.h"
#include "../debug.h"
#include "../list.h"
#include "../radmsg.h"
#include "../radsecproxy.h"
#include "../reverse_coa.h"
#include "../udp.h"
#include "../util.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void removequeue(struct gqueue *q); /* not in a header */

int numtests = 0;

static uint8_t *secret = (uint8_t *)"testing123";
static int secretlen = 10;
static char *literalrealm[] = {"Example.COM", NULL};
static char *regexprealm[] = {"/\\.example\\.net$/", NULL};

/* the last packet sent to the originating server */
static uint8_t *sentbuf;
static int sentlen, sentcount;

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

static int stubradput(struct server *server, unsigned char *buf, int len) {
    free(sentbuf);
    sentbuf = malloc(len);
    memcpy(sentbuf, buf, len);
    sentlen = len;
    sentcount++;
    return 1;
}

static struct protodefs stubpdef = {.clientradput = stubradput};

/* a CoA-ACK with its response authenticator over rqauth, with a Proxy-State attribute when asked */
static int coaack(uint8_t *pkt, uint8_t id, int withattr, const uint8_t *rqauth) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int len = withattr ? 26 : 20;

    memset(pkt, 0, 26);
    pkt[0] = RAD_CoA_ACK;
    pkt[1] = id;
    pkt[3] = len;
    if (withattr) {
        pkt[20] = RAD_Attr_Proxy_State;
        pkt[21] = 6;
        memcpy(pkt + 22, "\xde\xad\xbe\xef", 4);
    }
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, pkt, 4);
    EVP_DigestUpdate(ctx, rqauth, 16);
    EVP_DigestUpdate(ctx, pkt + 20, len - 20);
    EVP_DigestUpdate(ctx, secret, secretlen);
    EVP_DigestFinal_ex(ctx, pkt + 4, NULL);
    EVP_MD_CTX_free(ctx);
    return len;
}

/* a client block with one entry, registered for reverse coa; a sibling when asked */
static struct client *newclientfull(uint8_t type, char *name, char *nasid, char **realms, char *addr, int sibling) {
    struct clsrvconf *conf = calloc(1, sizeof(struct clsrvconf));
    struct client *client = calloc(1, sizeof(struct client));
    struct sockaddr_in sin = {.sin_family = AF_INET};

    conf->name = name;
    conf->type = type;
    conf->secret = secret;
    conf->secret_len = secretlen;
    conf->nas_identifier = nasid;
    conf->reverse_coa_realms = realms;
    conf->reverse_coa_sibling = sibling;
    reverse_coa_compile_realms(conf);
    reverse_coa_compile_nas_identifier(conf);
    conf->coaport = 3799;
    conf->reverse_coa_timeout = 30;
    conf->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(conf->lock, NULL);
    conf->clients = list_create();
    list_push(conf->clients, client);
    inet_pton(AF_INET, addr, &sin.sin_addr);
    client->conf = conf;
    client->addr = addr_copy((struct sockaddr *)&sin);
    client->identity = strdup(name);
    pthread_mutex_init(&client->lock, NULL);
    client->replyq = newqueue();
    client->reverse_coa_route = reverse_coa_route_new(client);
    register_reverse_coa_client(client);
    return client;
}

static struct client *newclienttype(uint8_t type, char *name, char *nasid, char **realms, char *addr) {
    return newclientfull(type, name, nasid, realms, addr, 0);
}

static struct client *newclient(char *name, char *nasid, char **realms, char *addr) {
    return newclienttype(RAD_UDP, name, nasid, realms, addr);
}

/* a tls client that is another proxy of this site */
static struct client *newsibling(char *name, char *addr) {
    return newclientfull(RAD_TLS, name, NULL, NULL, addr, 1);
}

static void freeclient(struct client *client) {
    unregister_reverse_coa_client(client);
    free_reverse_coa_rqs(client);
    reverse_coa_route_deref(client->reverse_coa_route);
    removequeue(client->replyq);
    pthread_mutex_destroy(&client->lock);
    free(client->addr);
    free(client->identity);
    list_free(client->conf->clients);
    reverse_coa_free_realms(client->conf);
    reverse_coa_free_nas_identifier(client->conf);
    pthread_mutex_destroy(client->conf->lock);
    free(client->conf->lock);
    free(client->conf);
    free(client);
}

/* a server with acceptReverseCoA, answered through stubradput */
static struct server *newserver(char *name) {
    struct server *server = calloc(1, sizeof(struct server));

    server->conf = calloc(1, sizeof(struct clsrvconf));
    server->conf->name = name;
    server->conf->type = RAD_TLS;
    server->conf->secret = secret;
    server->conf->secret_len = secretlen;
    server->conf->pdef = &stubpdef;
    server->conf->accept_reverse_coa = 1;
    server->reverse_coa_seen = calloc(MAX_REQUESTS, sizeof(struct coa_dedup_slot));
    pthread_mutex_init(&server->reverse_coa_lock, NULL);
    return server;
}

static void freeserver(struct server *server) {
    drain_coa_dedup(server);
    free(server->reverse_coa_seen);
    pthread_mutex_destroy(&server->reverse_coa_lock);
    free(server->conf);
    free(server);
}

/* a request with Operator-Name and NAS-Identifier when given */
static struct radmsg *request(uint8_t code, uint8_t id, char *opname, char *nasid) {
    struct radmsg *msg = radmsg_init(code, id, NULL);

    if (opname)
        radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, strlen(opname), opname), 0);
    if (nasid)
        radmsg_add(msg, maketlv(RAD_Attr_NAS_Identifier, strlen(nasid), nasid), 0);
    return msg;
}

/* routes msg from server and frees it */
static int dispatch(struct server *server, struct radmsg *msg) {
    int result = _internal_dispatch_reverse_coa(server, NULL, msg);

    radmsg_free(msg);
    return result;
}

/* the request queued for the client, NULL if none */
static struct request *queued(struct client *client) {
    return (struct request *)list_shift(client->replyq->entries);
}

int main(int argc, char *argv[]) {
    uint8_t rqauth[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    struct client *nas, *proxy;
    struct server *server;

    debug_init("t_reverse_coa");
    init_reverse_coa();

    /* response authenticator */
    {
        uint8_t pkt[26], other[16];
        int len = coaack(pkt, 7, 0, rqauth);

        test_ok(radmsg_validate_response_auth(pkt, len, secret, secretlen, rqauth), "correct authenticator");
        memcpy(other, rqauth, 16);
        other[0] ^= 0xff;
        test_ok(!radmsg_validate_response_auth(pkt, len, secret, secretlen, other), "wrong request authenticator");
        test_ok(!radmsg_validate_response_auth(pkt, 19, secret, secretlen, rqauth), "short");
        memset(pkt + 20, 0xff, 6);
        test_ok(radmsg_validate_response_auth(pkt, 20, secret, secretlen, rqauth), "declared length used");
        test_ok(!radmsg_validate_response_auth(pkt, 26, secret, secretlen, rqauth), "trailing bytes fail");
        len = coaack(pkt, 8, 1, rqauth);
        test_ok(radmsg_validate_response_auth(pkt, len, secret, secretlen, rqauth), "with attribute");
    }

    /* pending response lookup */
    {
        struct client *client = newclient("udp", NULL, NULL, "192.0.2.100");
        struct sockaddr_in from = {.sin_family = AF_INET, .sin_port = htons(3799)};
        struct request dummy; /* not a real request, never freed */
        uint8_t pkt[26];
        int len = coaack(pkt, 7, 0, rqauth);

        inet_pton(AF_INET, "192.0.2.100", &from.sin_addr);
        memset(&dummy, 0, sizeof(dummy));
        client->sock = 42;
        client->reverse_coa_rqs = calloc(MAX_REQUESTS, sizeof(struct rqout));
        client->reverse_coa_rqs[7].rq = &dummy;
        memcpy(client->reverse_coa_rqs[7].sentauth, rqauth, 16); /* sentauth as send_coa_to_client stores it */
        test_ok(findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len) == client, "response matched");
        test_ok(!findreversecoaclient(client->conf, 99, (struct sockaddr *)&from, pkt, len), "wrong socket");
        from.sin_addr.s_addr ^= 1;
        test_ok(!findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len), "wrong source");
        from.sin_addr.s_addr ^= 1;
        client->reverse_coa_rqs[7].sentauth[0] ^= 0xff;
        test_ok(!findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len), "other request authenticator");
        client->reverse_coa_rqs[7].sentauth[0] ^= 0xff;
        pkt[1] = 8;
        test_ok(!findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len), "nothing pending for the id");
        client->reverse_coa_rqs[7].rq = NULL;
        freeclient(client);
    }

    /* token */
    {
        char token[REVERSE_COA_TOKEN_LEN + 1], token2[REVERSE_COA_TOKEN_LEN + 1], parsed[REVERSE_COA_TOKEN_LEN + 1];
        struct tlv *attr;

        test_ok(reverse_coa_newtoken(token) && strlen(token) == REVERSE_COA_TOKEN_LEN, "token length");
        test_ok(reverse_coa_newtoken(token2) && strcmp(token, token2) != 0, "tokens differ");
        attr = makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, token);
        test_ok(attr && attr->l == REVERSE_COA_TOKEN_LEN + 1 && attr->v[0] == 8, "token as attribute 241.8");
        test_ok(reverse_coa_token(attr, parsed) && !strcmp(parsed, token), "token parses");
        freetlv(attr);
        attr = makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, 9, (void *)"nas-1.lab");
        test_ok(!reverse_coa_token(attr, parsed), "foreign identifier rejected");
        freetlv(attr);
        test_ok(!reverse_coa_token(NULL, parsed), "missing attribute rejected");

        /* ReverseCoATokenKey: the token follows the identity */
        reverse_coa_settokenkey("sixteen-char-key");
        test_ok(reverse_coa_peertoken(token, "CN=nas-1,O=lab", NULL) && strlen(token) == REVERSE_COA_TOKEN_LEN, "keyed token length");
        test_ok(reverse_coa_peertoken(token2, "CN=nas-1,O=lab", NULL) && !strcmp(token, token2), "keyed token is the same for the same identity");
        test_ok(reverse_coa_peertoken(token2, "CN=nas-2,O=lab", NULL) && strcmp(token, token2) != 0, "keyed token differs per identity");
        {
            struct sockaddr_in a = {.sin_family = AF_INET}, b = {.sin_family = AF_INET};
            char token3[REVERSE_COA_TOKEN_LEN + 1];

            inet_pton(AF_INET, "198.51.100.1", &a.sin_addr);
            inet_pton(AF_INET, "198.51.100.2", &b.sin_addr);
            test_ok(reverse_coa_peertoken(token2, "CN=nas-1,O=lab", (struct sockaddr *)&a) && strcmp(token, token2) != 0, "the peer address is part of the keyed token");
            test_ok(reverse_coa_peertoken(token3, "CN=nas-1,O=lab", (struct sockaddr *)&a) && !strcmp(token2, token3), "same identity and address, same token");
            test_ok(reverse_coa_peertoken(token3, "CN=nas-1,O=lab", (struct sockaddr *)&b) && strcmp(token2, token3) != 0, "one certificate from two addresses, two tokens");
        }
        /* the token of a nas that has sent a request: its identity and what it says it is */
        {
            struct radmsg *rq1 = request(RAD_Access_Request, 1, NULL, "ap-1"), *rq2 = request(RAD_Access_Request, 2, NULL, "ap-2");
            struct radmsg *noid = request(RAD_Access_Request, 3, NULL, NULL), *bare = request(RAD_Access_Request, 4, NULL, NULL);
            struct sockaddr_in a = {.sin_family = AF_INET}, b = {.sin_family = AF_INET};
            uint8_t lan[4] = {10, 0, 0, 1};
            char token3[REVERSE_COA_TOKEN_LEN + 1];

            inet_pton(AF_INET, "198.51.100.1", &a.sin_addr);
            inet_pton(AF_INET, "198.51.100.2", &b.sin_addr);
            radmsg_add(noid, maketlv(RAD_Attr_NAS_IP_Address, 4, lan), 0);
            test_ok(reverse_coa_nastoken(token, "CN=fleet,O=lab", rq1, (struct sockaddr *)&a) && strlen(token) == REVERSE_COA_TOKEN_LEN, "nas token length");
            test_ok(reverse_coa_nastoken(token2, "CN=fleet,O=lab", rq1, (struct sockaddr *)&b) && !strcmp(token, token2), "same nas from another address, same token");
            test_ok(reverse_coa_nastoken(token2, "CN=fleet,O=lab", rq1, NULL) && !strcmp(token, token2), "the address is not part of it");
            test_ok(reverse_coa_nastoken(token2, "CN=fleet,O=lab", rq2, (struct sockaddr *)&a) && strcmp(token, token2) != 0, "another nas on the certificate, another token");
            test_ok(reverse_coa_nastoken(token2, "CN=other,O=lab", rq1, (struct sockaddr *)&a) && strcmp(token, token2) != 0, "same nas-identifier on another certificate, another token");
            test_ok(reverse_coa_nastoken(token2, "CN=fleet,O=lab", noid, (struct sockaddr *)&a) && strcmp(token, token2) != 0, "no nas-identifier: the nas address instead");
            test_ok(reverse_coa_nastoken(token3, "CN=fleet,O=lab", noid, (struct sockaddr *)&b) && !strcmp(token2, token3), "the nas address from another peer address, same token");
            test_ok(reverse_coa_nastoken(token2, "CN=fleet,O=lab", bare, (struct sockaddr *)&a) && reverse_coa_peertoken(token3, "CN=fleet,O=lab", (struct sockaddr *)&a) && !strcmp(token2, token3), "neither: the peer address, as before the first request");
            radmsg_free(rq1);
            radmsg_free(rq2);
            radmsg_free(noid);
            radmsg_free(bare);
        }
        reverse_coa_settokenkey("another-key-of-16");
        test_ok(reverse_coa_peertoken(token2, "CN=nas-1,O=lab", NULL) && strcmp(token, token2) != 0, "keyed token differs per key");
        test_ok(reverse_coa_peertoken(token2, NULL, NULL) && strlen(token2) == REVERSE_COA_TOKEN_LEN, "no identity gives a random token");
        reverse_coa_settokenkey(NULL);
        test_ok(reverse_coa_peertoken(token2, "CN=nas-1,O=lab", NULL) && strcmp(token, token2) != 0, "without a key the token is random");
    }

    /* operator attributes */
    {
        struct radmsg *msg = request(RAD_CoA_Request, 1, "1example.com", NULL);
        uint32_t code = 0;

        radmsg_add(msg, maketlv(RAD_Attr_User_Name, 8, (void *)"user@abc"), 0);
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Original_Packet_Code, 4, &code), 0);
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, 5, (void *)"nas-1"), 0);
        strip_operator_attrs(msg);
        test_ok(!radmsg_gettype(msg, RAD_Attr_Operator_Name), "operator-name stripped");
        test_ok(!radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier), "operator-nas-identifier stripped");
        test_ok(radmsg_getexttype(msg, RAD_ExtAttr_Original_Packet_Code) && radmsg_gettype(msg, RAD_Attr_User_Name), "other attributes kept");
        radmsg_free(msg);
    }

    /* operator-nas-identifier */
    {
        struct client *client = newclient("edge", NULL, NULL, "192.0.2.1");
        struct radmsg *msg = request(RAD_Access_Request, 1, NULL, NULL);
        struct tlv *attr;
        struct list *ext;
        char parsed[REVERSE_COA_TOKEN_LEN + 1];

        strcpy(client->token, "0123456789abcdef");
        test_ok(add_operator_nas_identifier(client, msg) && !radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier), "nothing added without operator-name");
        radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, 12, (void *)"4EXAMPLE:XX"), 0);
        attr = add_operator_nas_identifier(client, msg) ? radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier) : NULL;
        test_ok(attr && reverse_coa_token(attr, parsed) && !strcmp(parsed, client->token), "added next to operator-name");
        add_operator_nas_identifier(client, msg);
        ext = radmsg_getalltype(msg, RAD_ExtAttr_Operator_NAS_Identifier.t);
        test_eq(1, ext ? (int)list_count(ext) : 0, "no second operator-nas-identifier");
        list_free(ext);
        radmsg_free(msg);
        freeclient(client);
    }

    /* nas address */
    {
        struct radmsg *msg = request(RAD_Disconnect_Request, 1, NULL, NULL);
        struct sockaddr_storage ss;
        uint8_t v4[4] = {10, 0, 0, 69};
        uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

        test_ok(!reverse_coa_nas_addr(msg, &ss), "no address attribute");
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IPv6_Address, 16, v6), 0);
        test_ok(reverse_coa_nas_addr(msg, &ss) && ss.ss_family == AF_INET6 && !memcmp(&((struct sockaddr_in6 *)&ss)->sin6_addr, v6, 16), "nas-ipv6-address");
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, v4), 0);
        test_ok(reverse_coa_nas_addr(msg, &ss) && ss.ss_family == AF_INET && !memcmp(&((struct sockaddr_in *)&ss)->sin_addr, v4, 4) && !((struct sockaddr_in *)&ss)->sin_port, "nas-ip-address preferred");
        radmsg_free(msg);
    }

    /* nas identity */
    {
        struct client *client = newclient("mapped", "nas-m", NULL, "192.0.2.102");
        struct sockaddr_in6 sin6 = {.sin6_family = AF_INET6};
        struct radmsg *msg = request(RAD_CoA_Request, 1, NULL, NULL);
        uint8_t v4[4] = {192, 0, 2, 102};

        inet_pton(AF_INET6, "::ffff:192.0.2.102", &sin6.sin6_addr);
        free(client->addr);
        client->addr = addr_copy((struct sockaddr *)&sin6);
        test_ok(!_internal_match_nas_identifier(client, msg), "not named");
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, v4), 0);
        test_ok(_internal_match_nas_identifier(client, msg), "nas-ip-address on a v4-mapped client");
        radmsg_free(msg);
        msg = request(RAD_CoA_Request, 1, NULL, "nas-x");
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, 5, (void *)"nas-m"), 0);
        test_ok(_internal_match_nas_identifier(client, msg), "operator-nas-identifier");
        radmsg_free(msg);
        freeclient(client);
    }

    /* realm values of a block, compiled once */
    {
        struct clsrvconf conf;
        char *good[] = {"Example.COM", "/\\.example\\.net$/", NULL}, *bad[] = {"/[unclosed/", NULL};

        memset(&conf, 0, sizeof(conf));
        conf.reverse_coa_realms = good;
        test_ok(reverse_coa_compile_realms(&conf) && conf.reverse_coa_regexes, "realm values compiled");
        reverse_coa_free_realms(&conf);
        test_ok(!conf.reverse_coa_regexes, "compiled realm values freed");
        conf.reverse_coa_realms = bad;
        test_ok(!reverse_coa_compile_realms(&conf) && !conf.reverse_coa_regexes, "invalid regexp rejected");
    }

    /* relayed message-authenticator */
    {
        struct radmsg *nak = radmsg_init(RAD_Disconnect_NAK, 5, rqauth), *back;
        uint8_t stale[16], *buf = NULL;
        int len;

        memset(stale, 0x5a, 16);
        radmsg_add(nak, maketlvlongint(RAD_Attr_Error_Cause, RAD_Err_Unsupported_Extension), 0);
        radmsg_add(nak, maketlv(RAD_Attr_Message_Authenticator, 16, stale), 0);
        len = radmsg2buf(nak, secret, secretlen, &buf);
        back = buf2radmsg(buf, len, secret, secretlen, rqauth);
        test_ok(back && (back->authstate == RSP_RADMSG_INVALID || back->authstate == RSP_RADMSG_MSGAUTH_INVALID), "stale msgauth fails");
        radmsg_free(back);
        free(buf);
        memcpy(nak->auth, rqauth, 16);
        ensuremsgauthfront(nak);
        len = radmsg2buf(nak, secret, secretlen, &buf);
        back = buf2radmsg(buf, len, secret, secretlen, rqauth);
        test_ok(back && back->authstate == RSP_RADMSG_MSGAUTH_VALID, "fresh msgauth verifies");
        radmsg_free(back);
        free(buf);
        radmsg_free(nak);
    }

    /* pending */
    {
        struct client *client = newclient("idle", NULL, NULL, "192.0.2.101");

        test_ok(!client_has_pending_reverse_coa(client), "nothing sent");
        client->reverse_coa_rqs = calloc(MAX_REQUESTS, sizeof(struct rqout));
        test_ok(!client_has_pending_reverse_coa(client), "nothing pending");
        client->reverse_coa_rqs[200].rq = newrequest();
        client->reverse_coa_rqs[200].expiry.tv_sec = time(NULL) + 30;
        client->reverse_coa_pending = 1;
        test_ok(client_has_pending_reverse_coa(client), "pending set");
        client->reverse_coa_rqs[200].expiry.tv_sec = time(NULL) - 30;
        test_ok(!client_has_pending_reverse_coa(client) && !client->reverse_coa_rqs[200].rq, "expired slot cleared");
        freeclient(client);
    }

    server = newserver("hub");
    nas = newclient("nas", "nas-1", literalrealm, "192.0.2.10");
    proxy = newclient("proxy", NULL, NULL, "192.0.2.20");

    /* realm registry */
    {
        struct client *other = newclient("other", "nas-2", regexprealm, "192.0.2.30");
        struct request *rq;

        test_eq(0, dispatch(server, request(RAD_CoA_Request, 1, "1example.com", "nas-1")), "literal realm");
        rq = queued(nas);
        test_ok(rq != NULL, "case-insensitive match delivered");
        freerq(rq);
        test_eq(0, dispatch(server, request(RAD_CoA_Request, 2, "1ap.example.net", "nas-2")), "regexp realm");
        rq = queued(other);
        test_ok(rq != NULL, "regexp match delivered");
        freerq(rq);
        test_eq(RAD_Err_NAS_Identification_Mismatch, dispatch(server, request(RAD_CoA_Request, 3, "1example.com", "nas-2")), "nas not named 403");
        test_eq(RAD_Err_Missing_Attribute, dispatch(server, request(RAD_CoA_Request, 6, "1example.com", NULL)), "no nas identification at all 402");
        test_eq(RAD_Err_Request_Not_Routable, dispatch(server, request(RAD_CoA_Request, 4, "1example.org", "nas-1")), "unknown realm 502");
        test_ok(!queued(nas) && !queued(other), "nothing queued");
        unregister_reverse_coa_client(other);
        test_ok(!_internal_reverse_coa_route_target(other->reverse_coa_route), "unregister clears the target");
        test_eq(RAD_Err_Request_Not_Routable, dispatch(server, request(RAD_CoA_Request, 5, "1ap.example.net", "nas-2")), "unregistered realm 502");
        freeclient(other);
    }

    /* literal realm values before regexps */
    {
        static char *catchall[] = {"/\\.biz$/", NULL}, *named[] = {"example.biz", NULL};
        struct client *wide = newclienttype(RAD_TLS, "wide", NULL, catchall, "192.0.2.51");
        struct client *exact = newclienttype(RAD_TLS, "exact", NULL, named, "192.0.2.52");
        struct request *rq;

        test_eq(0, dispatch(server, request(RAD_CoA_Request, 40, "1example.biz", NULL)), "literal and regexp realm");
        rq = queued(exact);
        test_ok(rq && !queued(wide), "literal value before a regexp registered first");
        freerq(rq);
        freeclient(exact);
        freeclient(wide);
    }

    /* dispatch */
    {
        struct request *rq, *origin;
        struct radmsg *msg, *sent;
        uint8_t v4[4] = {192, 0, 2, 10};

        test_eq(0, dispatch(server, request(RAD_CoA_Request, 10, "1example.com", "nas-1")), "named nas");
        rq = queued(nas);
        sent = rq ? buf2radmsg(rq->replybuf, rq->replybuflen, secret, secretlen, NULL) : NULL;
        test_ok(sent && sent->authstate == RSP_RADMSG_MSGAUTH_VALID, "signed for the client");
        test_ok(sent && !radmsg_gettype(sent, RAD_Attr_Operator_Name) && !radmsg_getexttype(sent, RAD_ExtAttr_Operator_NAS_Identifier), "operator attributes removed");
        test_ok(sent && radmsg_gettype(sent, RAD_Attr_NAS_Identifier), "nas-identifier kept");
        test_ok(rq && rq->rqid == 10 && rq->to == server && sent && sent->id == rq->newid, "answers to the server");
        test_ok(rq && rq->to_override && ntohs(((struct sockaddr_in *)rq->to_override)->sin_port) == 3799, "sent to the coa port");
        radmsg_free(sent);
        freerq(rq);

        /* a plain rfc 5176 request names the nas by address */
        msg = request(RAD_CoA_Request, 11, NULL, NULL);
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, v4), 0);
        test_eq(0, dispatch(server, msg), "nas-ip-address without operator-name");
        rq = queued(nas);
        test_ok(rq != NULL, "delivered by address");
        freerq(rq);

        /* operator-nas-identifier names the connection, next to operator-name only */
        strcpy(nas->token, "0123456789abcdef");
        msg = request(RAD_CoA_Request, 12, "1example.org", NULL);
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
        test_eq(0, dispatch(server, msg), "token names the connection");
        rq = queued(nas);
        test_ok(rq != NULL, "delivered by token");
        freerq(rq);
        msg = request(RAD_CoA_Request, 13, NULL, NULL);
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
        test_eq(RAD_Err_Request_Not_Routable, dispatch(server, msg), "token without operator-name ignored");

        /* a keyed token follows the identity, so a fleet on one certificate shares it:
           the nas the request names gets the request, whichever connected first */
        {
            struct client *twin = newclient("nas-twin", "nas-2", literalrealm, "192.0.2.12");

            strcpy(twin->token, nas->token);
            msg = request(RAD_CoA_Request, 14, "1example.org", "nas-2");
            radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
            test_eq(0, dispatch(server, msg), "shared token, second nas named");
            rq = queued(twin);
            test_ok(rq != NULL, "delivered to the nas named");
            freerq(rq);
            test_ok(queued(nas) == NULL, "not to the first connection with the token");
            msg = request(RAD_CoA_Request, 15, "1example.org", "nas-1");
            radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
            test_eq(0, dispatch(server, msg), "shared token, first nas named");
            rq = queued(nas);
            test_ok(rq != NULL, "delivered to the first nas");
            freerq(rq);
            test_ok(queued(twin) == NULL, "not to the second");

            /* none named: the connection that sent a request most recently, so a nas that
               reconnected is reached while its old connection lingers */
            twin->last_request = time(NULL);
            nas->last_request = twin->last_request - 60;
            msg = request(RAD_CoA_Request, 16, "1example.org", NULL);
            radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
            test_eq(0, dispatch(server, msg), "shared token, none named");
            rq = queued(twin);
            test_ok(rq != NULL, "delivered to the connection that spoke last");
            freerq(rq);
            test_ok(queued(nas) == NULL, "not to the older one");
            nas->last_request = twin->last_request + 60;
            msg = request(RAD_CoA_Request, 17, "1example.org", NULL);
            radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
            test_eq(0, dispatch(server, msg), "shared token, the other one spoke last");
            rq = queued(nas);
            test_ok(rq != NULL, "delivered to the newer connection");
            freerq(rq);
            test_ok(queued(twin) == NULL, "not to the older one");
            nas->last_request = 0;
            freeclient(twin);
        }

        /* NASidentifier /regexp/: a fleet on one certificate, each connection told apart
           by the NAS-Identifier it sent; nothing learned yet matches nothing */
        {
            struct client *site_a = newclienttype(RAD_TLS, "fleet", "/^site-/", literalrealm, "198.51.100.1");
            struct client *site_b = newclienttype(RAD_TLS, "fleet", "/^site-/", literalrealm, "198.51.100.2");
            struct radmsg *acct;
            uint8_t lan[4] = {192, 168, 1, 1};
            char before[REVERSE_COA_TOKEN_LEN + 1];

            reverse_coa_settokenkey("sixteen-char-key");
            strcpy(site_a->token, "fedcba9876543210");
            strcpy(site_b->token, "fedcba9876543210");
            strcpy(before, site_a->token);
            msg = request(RAD_CoA_Request, 16, "1example.com", "site-b");
            test_eq(RAD_Err_NAS_Identification_Mismatch, dispatch(server, msg), "fleet block, nothing learned yet, nas not found");

            acct = request(RAD_Accounting_Request, 1, NULL, "site-a");
            radmsg_add(acct, maketlv(RAD_Attr_NAS_IP_Address, 4, lan), 0);
            learn_nas_identity(site_a, acct);
            radmsg_free(acct);
            acct = request(RAD_Accounting_Request, 2, NULL, "site-b");
            radmsg_add(acct, maketlv(RAD_Attr_NAS_IP_Address, 4, lan), 0);
            learn_nas_identity(site_b, acct);
            radmsg_free(acct);
            test_ok(strcmp(site_a->token, before) != 0 && strcmp(site_a->token, site_b->token) != 0, "a request sets the token from the nas-identifier, one per nas");
            test_ok(site_a->last_request > 0, "a request stamps the connection");
            test_ok(_internal_match_nas_identifier(site_b, msg = request(RAD_CoA_Request, 0, NULL, "site-b")), "learned nas-identifier matches");
            test_ok(!_internal_match_nas_identifier(site_a, msg), "and not the other site, same lan address");
            radmsg_free(msg);

            msg = request(RAD_CoA_Request, 17, "1example.com", "site-b");
            test_eq(0, dispatch(server, msg), "fleet block, nas named by learned nas-identifier");
            rq = queued(site_b);
            test_ok(rq != NULL, "delivered to site-b");
            freerq(rq);
            test_ok(queued(site_a) == NULL, "not to site-a");

            msg = request(RAD_CoA_Request, 18, "1example.com", "site-a");
            radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, site_a->token), 0);
            test_eq(0, dispatch(server, msg), "fleet block, token names site-a");
            rq = queued(site_a);
            test_ok(rq != NULL, "delivered to site-a by token");
            freerq(rq);
            test_ok(queued(site_b) == NULL, "not to site-b");

            /* site-a reconnects from another address: a new connection, the same nas, the same
               token after its first request; the old connection has not been reaped */
            {
                struct client *site_a2 = newclienttype(RAD_TLS, "fleet", "/^site-/", literalrealm, "203.0.113.9");

                acct = request(RAD_Accounting_Request, 3, NULL, "site-a");
                radmsg_add(acct, maketlv(RAD_Attr_NAS_IP_Address, 4, lan), 0);
                learn_nas_identity(site_a2, acct);
                radmsg_free(acct);
                test_ok(!strcmp(site_a2->token, site_a->token), "same nas from a new address, same token");
                site_a->last_request = site_a2->last_request - 60;
                msg = request(RAD_CoA_Request, 21, "1example.com", NULL);
                radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, site_a->token), 0);
                test_eq(0, dispatch(server, msg), "token on two connections, none named");
                rq = queued(site_a2);
                test_ok(rq != NULL, "delivered on the connection that spoke last");
                freerq(rq);
                test_ok(queued(site_a) == NULL, "not on the lingering one");
                freeclient(site_a2);
            }

            msg = request(RAD_CoA_Request, 19, "1example.com", "site-c");
            test_eq(RAD_Err_NAS_Identification_Mismatch, dispatch(server, msg), "fleet block, unknown nas is 403");
            msg = request(RAD_CoA_Request, 20, "1example.com", "other-b");
            test_eq(RAD_Err_NAS_Identification_Mismatch, dispatch(server, msg), "fleet block, name outside the regexp is 403");

            reverse_coa_settokenkey(NULL);
            freeclient(site_a);
            freeclient(site_b);
        }

        /* a sibling proxy of the site: a request for a nas not held here is handed to it,
           once, with the operator attributes kept; one that came from a sibling is not */
        {
            struct client *sib = newsibling("edge2", "192.0.2.61");
            struct server *fromsib = newserver("edge2-in");
            struct radmsg *fwd;

            fromsib->conf->reverse_coa_sibling = 1;
            msg = request(RAD_CoA_Request, 30, "1example.com", "nas-9");
            radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, "00000000deadbeef"), 0);
            test_eq(0, dispatch(server, msg), "nas not here, handed to the sibling");
            rq = queued(sib);
            fwd = rq ? buf2radmsg(rq->replybuf, rq->replybuflen, secret, secretlen, NULL) : NULL;
            test_ok(fwd && radmsg_gettype(fwd, RAD_Attr_Operator_Name) && radmsg_getexttype(fwd, RAD_ExtAttr_Operator_NAS_Identifier), "operator attributes kept for the sibling");
            test_ok(rq && rq->to == server, "the answer goes to the server");
            radmsg_free(fwd);
            freerq(rq);
            test_ok(!queued(nas), "not to the local nas");

            msg = request(RAD_CoA_Request, 31, "1example.com", "nas-9");
            test_eq(RAD_Err_NAS_Identification_Mismatch, dispatch(fromsib, msg), "from a sibling, nas not here: 403, not handed on");
            test_ok(!queued(sib) && !queued(nas), "nothing queued");

            msg = request(RAD_CoA_Request, 32, "1example.com", "nas-1");
            test_eq(0, dispatch(server, msg), "nas held here");
            rq = queued(nas);
            test_ok(rq && !queued(sib), "delivered here, not to the sibling");
            freerq(rq);

            msg = request(RAD_CoA_Request, 33, "1example.org", "nas-9");
            test_eq(0, dispatch(server, msg), "realm not served here, handed to the sibling");
            rq = queued(sib);
            test_ok(rq != NULL, "handed by realm");
            freerq(rq);
            msg = request(RAD_CoA_Request, 34, "1example.org", "nas-9");
            test_eq(RAD_Err_Request_Not_Routable, dispatch(fromsib, msg), "from a sibling, realm not served: 502");

            msg = request(RAD_CoA_Request, 35, "1example.com", NULL);
            test_eq(RAD_Err_Missing_Attribute, dispatch(fromsib, msg), "from a sibling, nothing names a nas: 402");

            freeserver(fromsib);
            freeclient(sib);
        }

        /* a nak that says "not here" moves the request to the next candidate with a fresh
           request: 502 from a proxy of the realm, 403 or 502 from a sibling; anything else
           is relayed, and a hub never retries a 403 */
        {
            struct client *p1 = newclienttype(RAD_TLS, "p1", NULL, literalrealm, "192.0.2.71");
            struct client *p2 = newclienttype(RAD_TLS, "p2", NULL, literalrealm, "192.0.2.72");
            struct client *s1 = newsibling("s1", "192.0.2.81");
            struct client *s2 = newsibling("s2", "192.0.2.82");
            struct radmsg *nak, *back;
            struct request *rq2;
            uint8_t *buf, auth[16];
            int len;

            /* the request through the server path, so the duplicate slot records the route */
            msg = request(RAD_CoA_Request, 40, "1example.com", "nas-9");
            memcpy(auth, msg->auth, 16);
            len = radmsg2buf(msg, secret, secretlen, &buf);
            sentcount = 0;
            test_ok(try_handle_reverse_coa_request(server, buf, len) && !sentcount, "sent to the first proxy of the realm");
            rq = queued(p1);
            test_ok(rq && !queued(p2), "the first proxy has it");
            nak = radmsg_init(RAD_CoA_NAK, rq ? rq->newid : 0, NULL);
            radmsg_add(nak, make_error_cause_tlv(RAD_Err_Request_Not_Routable), 0);
            test_ok(forward_coa_response(p1, nak) && !sentcount, "502 from the first proxy is not relayed");
            rq2 = queued(p2);
            test_ok(rq2 && rq2->rqid == 40 && rq2->to == server && rq2 != rq, "the second proxy gets a fresh request for the same one");
            test_ok(_internal_reverse_coa_route_target(server->reverse_coa_seen[40].route) == p2, "retransmissions follow it");
            radmsg_free(nak);
            nak = radmsg_init(RAD_CoA_ACK, rq2 ? rq2->newid : 0, NULL);
            test_ok(forward_coa_response(p2, nak) && sentcount == 1, "the ack from the second proxy is relayed");
            back = buf2radmsg(sentbuf, sentlen, secret, secretlen, auth);
            test_ok(back && back->code == RAD_CoA_ACK && back->id == 40, "under the original id");
            radmsg_free(back);
            radmsg_free(nak);
            freerq(rq);
            freerq(rq2);
            radmsg_free(msg);

            /* 403 from a proxy of the realm is the site's answer, relayed */
            msg = request(RAD_CoA_Request, 41, "1example.com", "nas-9");
            test_eq(0, dispatch(server, msg), "sent again");
            rq = queued(p1);
            nak = radmsg_init(RAD_CoA_NAK, rq ? rq->newid : 0, NULL);
            radmsg_add(nak, make_error_cause_tlv(RAD_Err_NAS_Identification_Mismatch), 0);
            sentcount = 0;
            test_ok(forward_coa_response(p1, nak) && sentcount == 1 && !queued(p2), "403 from a proxy relayed, not retried");
            radmsg_free(nak);
            freerq(rq);

            /* 503 is an answer about the session, relayed */
            msg = request(RAD_CoA_Request, 42, "1example.com", "nas-9");
            test_eq(0, dispatch(server, msg), "sent again");
            rq = queued(p1);
            nak = radmsg_init(RAD_CoA_NAK, rq ? rq->newid : 0, NULL);
            radmsg_add(nak, make_error_cause_tlv(503), 0);
            sentcount = 0;
            test_ok(forward_coa_response(p1, nak) && sentcount == 1 && !queued(p2), "503 relayed, not retried");
            radmsg_free(nak);
            freerq(rq);

            /* every candidate says 502: the last nak is relayed */
            msg = request(RAD_CoA_Request, 43, "1example.com", "nas-9");
            test_eq(0, dispatch(server, msg), "sent again");
            rq = queued(p1);
            nak = radmsg_init(RAD_CoA_NAK, rq ? rq->newid : 0, NULL);
            radmsg_add(nak, make_error_cause_tlv(RAD_Err_Request_Not_Routable), 0);
            sentcount = 0;
            test_ok(forward_coa_response(p1, nak) && !sentcount, "first 502 not relayed");
            freerq(rq);
            rq = queued(p2);
            nak->id = rq ? rq->newid : 0;
            test_ok(forward_coa_response(p2, nak) && sentcount == 1, "last 502 relayed");
            radmsg_free(nak);
            freerq(rq);

            /* at the edge: a realm not served here goes to the first sibling; its 403
               means not there, the second sibling gets it */
            msg = request(RAD_CoA_Request, 44, "1example.org", "nas-9");
            test_eq(0, dispatch(server, msg), "handed to the first sibling");
            rq = queued(s1);
            test_ok(rq && !queued(s2), "the first sibling has it");
            nak = radmsg_init(RAD_CoA_NAK, rq ? rq->newid : 0, NULL);
            radmsg_add(nak, make_error_cause_tlv(RAD_Err_NAS_Identification_Mismatch), 0);
            sentcount = 0;
            test_ok(forward_coa_response(s1, nak) && !sentcount, "403 from the first sibling not relayed");
            rq2 = queued(s2);
            test_ok(rq2 && rq2->rqid == 44, "the second sibling gets it");
            radmsg_free(nak);
            nak = radmsg_init(RAD_CoA_ACK, rq2 ? rq2->newid : 0, NULL);
            test_ok(forward_coa_response(s2, nak) && sentcount == 1, "the second sibling's ack relayed");
            radmsg_free(nak);
            freerq(rq);
            freerq(rq2);

            /* switched off: the first answer is the answer */
            reverse_coa_setretry(0);
            msg = request(RAD_CoA_Request, 45, "1example.com", "nas-9");
            test_eq(0, dispatch(server, msg), "sent again");
            rq = queued(p1);
            nak = radmsg_init(RAD_CoA_NAK, rq ? rq->newid : 0, NULL);
            radmsg_add(nak, make_error_cause_tlv(RAD_Err_Request_Not_Routable), 0);
            sentcount = 0;
            test_ok(forward_coa_response(p1, nak) && sentcount == 1 && !queued(p2), "retry off: 502 relayed");
            radmsg_free(nak);
            freerq(rq);
            reverse_coa_setretry(1);

            freeclient(s2);
            freeclient(s1);
            freeclient(p2);
            freeclient(p1);
        }

        /* never back to the sender */
        origin = newrequest();
        origin->from = nas;
        origin->msg = request(RAD_CoA_Request, 18, "1example.com", "nas-1");
        test_eq(RAD_Err_Request_Not_Routable, route_reverse_coa_from_client(origin), "not back to the sender");
        test_ok(!queued(nas), "nothing queued for the sender");
        freerq(origin);
        origin = newrequest();
        origin->from = proxy;
        origin->msg = request(RAD_CoA_Request, 19, NULL, "nas-1");
        test_eq(RAD_Err_Request_Not_Routable, route_reverse_coa_from_client(origin), "client request without operator-name 502");
        test_ok(!queued(nas), "nothing queued without operator-name");
        freerq(origin);
    }

    /* duplicates */
    {
        struct radmsg *msg = request(RAD_CoA_Request, 20, "1example.org", NULL), *nak;
        struct tlv *attr;
        uint8_t *buf, *copy;
        int len = radmsg2buf(msg, secret, secretlen, &buf);

        copy = malloc(len);
        memcpy(copy, buf, len);
        sentcount = 0;
        test_ok(try_handle_reverse_coa_request(server, copy, len), "request taken");
        nak = sentcount ? buf2radmsg(sentbuf, sentlen, secret, secretlen, msg->auth) : NULL;
        attr = nak ? radmsg_gettype(nak, RAD_Attr_Error_Cause) : NULL;
        test_ok(nak && nak->code == RAD_CoA_NAK && nak->id == 20 && nak->authstate == RSP_RADMSG_MSGAUTH_VALID, "nak signed for the server");
        test_ok(attr && tlv2longint(attr) == RAD_Err_Request_Not_Routable, "error-cause 502");
        radmsg_free(nak);
        test_ok(server->reverse_coa_seen[20].occupied && server->reverse_coa_seen[20].replybuf, "slot holds the reply");
        copy = malloc(len);
        memcpy(copy, buf, len);
        test_ok(try_handle_reverse_coa_request(server, copy, len) && sentcount == 2, "duplicate answered from the slot");
        test_eq(1, _internal_is_coa_duplicate(server, msg), "duplicate");
        msg->auth[0] ^= 0xff;
        test_eq(0, _internal_is_coa_duplicate(server, msg), "other authenticator is new");
        msg->auth[0] ^= 0xff;
        server->reverse_coa_seen[20].received -= 300;
        test_ok(!_internal_is_coa_duplicate(server, msg) && !server->reverse_coa_seen[20].occupied, "expired slot cleared");
        _internal_record_coa_dedup(server, 20, msg->auth);
        test_ok(server->reverse_coa_seen[20].occupied && !server->reverse_coa_seen[20].replybuf, "recorded without a reply");
        test_eq(1, _internal_is_coa_duplicate(server, msg), "duplicate while pending");
        free(buf);
        radmsg_free(msg);

        /* event-timestamp within the window */
        msg = request(RAD_CoA_Request, 21, "1example.org", NULL);
        radmsg_add(msg, maketlvlongint(RAD_Attr_Event_Timestamp, (uint32_t)time(NULL) - 3600), 0);
        len = radmsg2buf(msg, secret, secretlen, &buf);
        sentcount = 0;
        test_ok(try_handle_reverse_coa_request(server, buf, len) && !sentcount && !server->reverse_coa_seen[21].occupied, "stale event-timestamp dropped");
        radmsg_free(msg);
        msg = request(RAD_CoA_Request, 22, "1example.org", NULL);
        radmsg_add(msg, maketlvlongint(RAD_Attr_Event_Timestamp, (uint32_t)time(NULL)), 0);
        len = radmsg2buf(msg, secret, secretlen, &buf);
        test_ok(try_handle_reverse_coa_request(server, buf, len) && sentcount == 1, "current event-timestamp taken");
        radmsg_free(msg);
    }

    /* response pairing */
    {
        struct radmsg *msg = request(RAD_Disconnect_Request, 30, "1example.com", "nas-1"), *resp, *back;
        struct request *rq, *origin;
        uint8_t auth[16], id;

        memcpy(auth, msg->auth, 16);
        test_eq(0, dispatch(server, msg), "disconnect sent");
        rq = queued(nas);
        id = rq ? rq->newid : 0;
        freerq(rq);
        resp = radmsg_init(RAD_CoA_ACK, id, NULL);
        test_ok(!forward_coa_response(nas, resp) && nas->reverse_coa_rqs[id].rq, "coa-ack does not answer a disconnect");
        resp->code = RAD_Disconnect_ACK;
        sentcount = 0;
        test_ok(forward_coa_response(nas, resp) && !nas->reverse_coa_rqs[id].rq, "disconnect-ack answers");
        back = sentcount ? buf2radmsg(sentbuf, sentlen, secret, secretlen, auth) : NULL;
        test_ok(back && back->code == RAD_Disconnect_ACK && back->id == 30 && back->authstate == RSP_RADMSG_MSGAUTH_VALID, "relayed under the original id");
        test_ok(!forward_coa_response(nas, resp), "nothing pending for the id");
        radmsg_free(back);
        radmsg_free(resp);

        /* a request from a client is answered by the response */
        origin = newrequest();
        origin->from = proxy;
        origin->msg = request(RAD_Disconnect_Request, 31, "1example.com", "nas-1");
        test_eq(0, route_reverse_coa_from_client(origin), "client request routed");
        rq = queued(nas);
        id = rq ? rq->newid : 0;
        test_ok(rq && rq->origin == origin, "origin kept");
        freerq(rq);
        resp = radmsg_init(RAD_Disconnect_ACK, id, NULL);
        test_ok(forward_coa_response(nas, resp), "answered");
        rq = queued(proxy);
        test_ok(rq == origin && rq->replybuf[0] == RAD_Disconnect_ACK && rq->replybuf[1] == 31, "client request answered");
        freerq(rq);
        freerq(origin);
        radmsg_free(resp);
    }

    freeclient(proxy);
    freeclient(nas);
    freeserver(server);
    free(sentbuf);

    printf("1..%d\n", numtests);
    return 0;
}
