/* Copyright (c) 2026, Nova Labs */
/* See LICENSE for licensing information. */

#include "../radmsg.h"
#include "../radsecproxy.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration: defined in udp.c, not in the public header */
struct client *find_reverse_coa_client_for_response(struct clsrvconf *p, int sock,
                                                    struct sockaddr *from,
                                                    const uint8_t *buf, int len);

int numtests = 0;

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

int main(int argc, char *argv[]) {
    /* test: IS_COA_REQUEST classifies correctly */
    test_ok(IS_COA_REQUEST(RAD_CoA_Request), "IS_COA_REQUEST(CoA-Request)");
    test_ok(IS_COA_REQUEST(RAD_Disconnect_Request), "IS_COA_REQUEST(Disconnect-Request)");
    test_ok(!IS_COA_REQUEST(RAD_CoA_ACK), "!IS_COA_REQUEST(CoA-ACK)");
    test_ok(!IS_COA_REQUEST(RAD_CoA_NAK), "!IS_COA_REQUEST(CoA-NAK)");
    test_ok(!IS_COA_REQUEST(RAD_Access_Request), "!IS_COA_REQUEST(Access-Request)");
    test_ok(!IS_COA_REQUEST(RAD_Accounting_Request), "!IS_COA_REQUEST(Accounting-Request)");

    /* test: IS_COA_RESPONSE classifies correctly */
    test_ok(IS_COA_RESPONSE(RAD_CoA_ACK), "IS_COA_RESPONSE(CoA-ACK)");
    test_ok(IS_COA_RESPONSE(RAD_CoA_NAK), "IS_COA_RESPONSE(CoA-NAK)");
    test_ok(IS_COA_RESPONSE(RAD_Disconnect_ACK), "IS_COA_RESPONSE(Disconnect-ACK)");
    test_ok(IS_COA_RESPONSE(RAD_Disconnect_NAK), "IS_COA_RESPONSE(Disconnect-NAK)");
    test_ok(!IS_COA_RESPONSE(RAD_CoA_Request), "!IS_COA_RESPONSE(CoA-Request)");
    test_ok(!IS_COA_RESPONSE(RAD_Access_Accept), "!IS_COA_RESPONSE(Access-Accept)");

    /* test: NEEDS_RADSIGN includes coa codes */
    test_ok(NEEDS_RADSIGN(RAD_CoA_Request), "NEEDS_RADSIGN(CoA-Request)");
    test_ok(NEEDS_RADSIGN(RAD_Disconnect_Request), "NEEDS_RADSIGN(Disconnect-Request)");
    test_ok(NEEDS_RADSIGN(RAD_CoA_ACK), "NEEDS_RADSIGN(CoA-ACK)");
    test_ok(NEEDS_RADSIGN(RAD_CoA_NAK), "NEEDS_RADSIGN(CoA-NAK)");
    test_ok(NEEDS_RADSIGN(RAD_Disconnect_ACK), "NEEDS_RADSIGN(Disconnect-ACK)");
    test_ok(NEEDS_RADSIGN(RAD_Disconnect_NAK), "NEEDS_RADSIGN(Disconnect-NAK)");
    test_ok(!NEEDS_RADSIGN(RAD_Access_Request), "!NEEDS_RADSIGN(Access-Request)");
    test_ok(!NEEDS_RADSIGN(RAD_Status_Server), "!NEEDS_RADSIGN(Status-Server)");

    /* test: operator-name attribute encoding */
    {
        uint8_t auth[20] = {0};
        struct radmsg *msg = radmsg_init(RAD_CoA_Request, 1, auth);
        test_ok(msg != NULL, "radmsg_init for operator-name test");
        if (msg) {
            char opname[] = "1example.org";
            struct tlv *attr = maketlv(RAD_Attr_Operator_Name, strlen(opname), opname);
            test_ok(attr != NULL, "maketlv Operator-Name");
            if (attr) {
                int added = radmsg_add(msg, attr, 0);
                test_ok(added, "radmsg_add Operator-Name");

                struct tlv *retrieved = radmsg_gettype(msg, RAD_Attr_Operator_Name);
                test_ok(retrieved != NULL, "radmsg_gettype Operator-Name");
                if (retrieved) {
                    test_eq(strlen(opname), retrieved->l, "Operator-Name length");
                    test_ok(memcmp(retrieved->v, opname, retrieved->l) == 0, "Operator-Name value");
                }
            }
            radmsg_free(msg);
        }
    }

    /* test: operator-nas-identifier as extended attr 241.8 per rfc 8559 */
    {
        uint8_t auth[20] = {0};
        struct radmsg *msg = radmsg_init(RAD_CoA_Request, 1, auth);
        test_ok(msg != NULL, "radmsg_init for operator-nas-identifier test");
        if (msg) {
            char token[] = "nas-bldg-a";
            uint8_t val[1 + sizeof(token) - 1];
            val[0] = RAD_Extended_Operator_NAS_Id;
            memcpy(val + 1, token, sizeof(token) - 1);
            struct tlv *attr = maketlv(RAD_Attr_Extended_Type_1, sizeof(val), val);
            test_ok(attr != NULL, "maketlv Operator-NAS-Identifier (241.8)");
            if (attr) {
                int added = radmsg_add(msg, attr, 0);
                test_ok(added, "radmsg_add Operator-NAS-Identifier");

                struct tlv *retrieved = radmsg_gettype(msg, RAD_Attr_Extended_Type_1);
                test_ok(retrieved != NULL, "radmsg_gettype Extended-Type-1");
                if (retrieved) {
                    test_ok(retrieved->v[0] == RAD_Extended_Operator_NAS_Id,
                            "Operator-NAS-Identifier extended type byte");
                    test_eq(sizeof(val), retrieved->l, "Operator-NAS-Identifier total length");
                    test_ok(memcmp(retrieved->v + 1, token, sizeof(token) - 1) == 0,
                            "Operator-NAS-Identifier token value");
                }
            }
            radmsg_free(msg);
        }
    }

    /* test: error-cause attribute in nak message */
    {
        uint8_t auth[20] = {0};
        struct radmsg *msg = radmsg_init(RAD_CoA_NAK, 1, auth);
        test_ok(msg != NULL, "radmsg_init for error-cause test");
        if (msg) {
            uint32_t error_cause = htonl(RAD_Err_Request_Not_Routable);
            struct tlv *attr = maketlv(RAD_Attr_Error_Cause, 4, &error_cause);
            test_ok(attr != NULL, "maketlv Error-Cause");
            if (attr) {
                int added = radmsg_add(msg, attr, 0);
                test_ok(added, "radmsg_add Error-Cause");

                struct tlv *retrieved = radmsg_gettype(msg, RAD_Attr_Error_Cause);
                test_ok(retrieved != NULL, "radmsg_gettype Error-Cause");
                if (retrieved) {
                    test_eq(4, retrieved->l, "Error-Cause length");
                    uint32_t val = ntohl(*(uint32_t *)retrieved->v);
                    test_eq(RAD_Err_Request_Not_Routable, val, "Error-Cause value");
                }
            }
            radmsg_free(msg);
        }
    }

    /* test: radmsg2buf/buf2radmsg round-trip for coa-request with operator-name */
    {
        uint8_t auth[20] = {0};
        struct radmsg *msg = radmsg_init(RAD_CoA_Request, 7, auth);
        test_ok(msg != NULL, "round-trip: radmsg_init");
        if (msg) {
            char opname[] = "1test.realm";
            struct tlv *attr = maketlv(RAD_Attr_Operator_Name, strlen(opname), opname);
            radmsg_add(msg, attr, 0);

            uint8_t *buf = NULL;
            int len = radmsg2buf(msg, NULL, 0, &buf);
            test_ok(len > 0, "round-trip: radmsg2buf succeeds");
            test_ok(buf != NULL, "round-trip: buffer allocated");

            if (buf && len > 0) {
                struct radmsg *parsed = buf2radmsg(buf, len, NULL, 0, NULL);
                test_ok(parsed != NULL, "round-trip: buf2radmsg succeeds");
                if (parsed) {
                    test_eq(RAD_CoA_Request, parsed->code, "round-trip: code preserved");
                    test_eq(7, parsed->id, "round-trip: id preserved");

                    struct tlv *op = radmsg_gettype(parsed, RAD_Attr_Operator_Name);
                    test_ok(op != NULL, "round-trip: Operator-Name present");
                    if (op) {
                        test_eq(strlen(opname), op->l, "round-trip: Operator-Name length");
                        test_ok(memcmp(op->v, opname, op->l) == 0,
                                "round-trip: Operator-Name value");
                    }
                    radmsg_free(parsed);
                }
                free(buf);
            }
            radmsg_free(msg);
        }
    }

    /* test: radmsg_copy_attrs copies coa attributes between messages */
    {
        uint8_t auth[20] = {0};
        struct radmsg *src = radmsg_init(RAD_CoA_Request, 1, auth);
        struct radmsg *dst = radmsg_init(RAD_CoA_Request, 2, auth);
        test_ok(src != NULL && dst != NULL, "copy_attrs: init");
        if (src && dst) {
            char opname[] = "1copy.realm";
            struct tlv *attr = maketlv(RAD_Attr_Operator_Name, strlen(opname), opname);
            radmsg_add(src, attr, 0);

            int copied = radmsg_copy_attrs(dst, src, RAD_Attr_Operator_Name);
            test_eq(1, copied, "copy_attrs: copied 1 attribute");

            struct tlv *retrieved = radmsg_gettype(dst, RAD_Attr_Operator_Name);
            test_ok(retrieved != NULL, "copy_attrs: attribute present in dst");
            if (retrieved) {
                test_ok(memcmp(retrieved->v, opname, retrieved->l) == 0,
                        "copy_attrs: value matches");
            }

            int none = radmsg_copy_attrs(dst, src, RAD_Attr_Error_Cause);
            test_eq(0, none, "copy_attrs: 0 when type not present");
        }
        radmsg_free(src);
        radmsg_free(dst);
    }

    /* test: radmsg_validate_response_auth */
    {
        /* build a minimal CoA-ACK (code=44) with known fields, then compute
           the correct response authenticator with MD5 and verify the wrapper */
        const uint8_t secret[] = "testing123";
        const int secret_len = 10;
        const uint8_t req_auth[16] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
        };

        /* 20-byte packet: code=44 id=7 length=20 auth=zeros(placeholder) */
        uint8_t pkt[20];
        pkt[0] = 44;   /* CoA-ACK */
        pkt[1] = 7;    /* id */
        pkt[2] = 0;
        pkt[3] = 20;   /* length = 20 */
        memset(pkt + 4, 0, 16); /* will be replaced by computed auth */

        /* compute: MD5(code||id||length||req_auth||secret) */
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        const EVP_MD *md5 = EVP_md5();
        uint8_t computed[16];
        EVP_DigestInit_ex(ctx, md5, NULL);
        EVP_DigestUpdate(ctx, pkt, 4);           /* code+id+length */
        EVP_DigestUpdate(ctx, req_auth, 16);     /* request authenticator */
        /* no attributes in this packet */
        EVP_DigestUpdate(ctx, secret, secret_len);
        EVP_DigestFinal_ex(ctx, computed, NULL);
        EVP_MD_CTX_free(ctx);

        memcpy(pkt + 4, computed, 16);

        test_ok(radmsg_validate_response_auth(pkt, 20, secret, secret_len, req_auth) == 1,
                "validate_response_auth: correct auth passes");
        test_ok(radmsg_validate_response_auth(pkt, 20, (const uint8_t *)"wrongsecret", 11, req_auth) == 0,
                "validate_response_auth: wrong secret fails");

        uint8_t bad_req_auth[16];
        memcpy(bad_req_auth, req_auth, 16);
        bad_req_auth[0] ^= 0xff;
        test_ok(radmsg_validate_response_auth(pkt, 20, secret, secret_len, bad_req_auth) == 0,
                "validate_response_auth: wrong request_auth fails");

        /* flip a bit in packet to simulate tampered data */
        uint8_t tampered[20];
        memcpy(tampered, pkt, 20);
        tampered[4] ^= 0x01;
        test_ok(radmsg_validate_response_auth(tampered, 20, secret, secret_len, req_auth) == 0,
                "validate_response_auth: tampered auth bytes fails");

        test_ok(radmsg_validate_response_auth(pkt, 19, secret, secret_len, req_auth) == 0,
                "validate_response_auth: buflen < 20 fails");

        test_ok(radmsg_validate_response_auth(pkt, 20, secret, secret_len, req_auth) == 1,
                "validate_response_auth: minimal 20-byte packet passes again");

        /* test: len > 20 path — 26-byte packet with a 6-byte Proxy-State attribute */
        {
            uint8_t pkt26[26];
            pkt26[0] = 44;   /* CoA-ACK */
            pkt26[1] = 8;    /* id */
            pkt26[2] = 0;
            pkt26[3] = 26;   /* length = 26 */
            memset(pkt26 + 4, 0, 16); /* auth placeholder */
            /* Proxy-State attribute: type=33, len=6, 4-byte value */
            pkt26[20] = 33;
            pkt26[21] = 6;
            pkt26[22] = 0xde; pkt26[23] = 0xad; pkt26[24] = 0xbe; pkt26[25] = 0xef;

            EVP_MD_CTX *ctx26 = EVP_MD_CTX_new();
            uint8_t computed26[16];
            EVP_DigestInit_ex(ctx26, md5, NULL);
            EVP_DigestUpdate(ctx26, pkt26, 4);          /* code+id+length */
            EVP_DigestUpdate(ctx26, req_auth, 16);      /* request authenticator */
            EVP_DigestUpdate(ctx26, pkt26 + 20, 6);    /* attribute bytes */
            EVP_DigestUpdate(ctx26, secret, secret_len);
            EVP_DigestFinal_ex(ctx26, computed26, NULL);
            EVP_MD_CTX_free(ctx26);
            memcpy(pkt26 + 4, computed26, 16);

            test_ok(radmsg_validate_response_auth(pkt26, 26, secret, secret_len, req_auth) == 1,
                    "validate_response_auth: 26-byte packet with Proxy-State attribute passes");
        }

        /* test: padded buffer — declared_len < buflen. caller supplies len=20 from header;
           function must use that, not the buffer size. */
        {
            uint8_t pkt_pad[30];
            /* declared length in header = 20; rest of buffer is padding/noise */
            pkt_pad[0] = 44;   /* CoA-ACK */
            pkt_pad[1] = 9;    /* id */
            pkt_pad[2] = 0;
            pkt_pad[3] = 20;   /* declared length = 20, no attributes */
            memset(pkt_pad + 4, 0, 16);
            /* bytes 20-29 are noise — must not be included in hash */
            memset(pkt_pad + 20, 0xff, 10);

            EVP_MD_CTX *ctx_pad = EVP_MD_CTX_new();
            uint8_t computed_pad[16];
            EVP_DigestInit_ex(ctx_pad, md5, NULL);
            EVP_DigestUpdate(ctx_pad, pkt_pad, 4);       /* code+id+length */
            EVP_DigestUpdate(ctx_pad, req_auth, 16);     /* request authenticator */
            /* no attributes (declared len = 20) */
            EVP_DigestUpdate(ctx_pad, secret, secret_len);
            EVP_DigestFinal_ex(ctx_pad, computed_pad, NULL);
            EVP_MD_CTX_free(ctx_pad);
            memcpy(pkt_pad + 4, computed_pad, 16);

            test_ok(radmsg_validate_response_auth(pkt_pad, 20, secret, secret_len, req_auth) == 1,
                    "validate_response_auth: padded buffer uses caller-supplied len not buffer size");
            test_ok(radmsg_validate_response_auth(pkt_pad, 30, secret, secret_len, req_auth) == 0,
                    "validate_response_auth: extending len to include noise bytes fails");
        }
    }

    /* test: find_reverse_coa_client_for_response */
    {
        const uint8_t secret[] = "testing123";
        const int secret_len = 10;
        /* sentauth is what send_coa_to_client stores in rqout->sentauth — the
           response authenticator of the outgoing CoA request, i.e. the 16
           bytes that the NAS should echo back in its response auth field */
        const uint8_t sentauth[16] = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
        };

        /* build a 20-byte CoA-ACK whose response auth is computed as
           MD5(code||id||length||sentauth||secret) */
        uint8_t pkt[20];
        pkt[0] = RAD_CoA_ACK;
        pkt[1] = 7;   /* id that maps to slot 7 in rqout */
        pkt[2] = 0;
        pkt[3] = 20;
        memset(pkt + 4, 0, 16);

        {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            uint8_t computed[16];
            EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
            EVP_DigestUpdate(ctx, pkt, 4);
            EVP_DigestUpdate(ctx, sentauth, 16);
            EVP_DigestUpdate(ctx, secret, secret_len);
            EVP_DigestFinal_ex(ctx, computed, NULL);
            EVP_MD_CTX_free(ctx);
            memcpy(pkt + 4, computed, 16);
        }

        /* build conf and client scaffolding */
        pthread_mutex_t conf_lock = PTHREAD_MUTEX_INITIALIZER;
        struct clsrvconf conf;
        memset(&conf, 0, sizeof(conf));
        conf.clients = list_create();
        conf.lock = &conf_lock;
        conf.secret = (uint8_t *)secret;
        conf.secret_len = secret_len;
        conf.type = RAD_UDP;

        struct sockaddr_in client_addr = {.sin_family = AF_INET};
        inet_pton(AF_INET, "192.0.2.100", &client_addr.sin_addr);
        client_addr.sin_port = htons(12345); /* ephemeral auth port */

        struct client *cli = calloc(1, sizeof(struct client));
        cli->conf = &conf;
        cli->sock = 42;
        cli->addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in));
        memcpy(cli->addr, &client_addr, sizeof(struct sockaddr_in));
        cli->reverse_coa_rqs = calloc(MAX_REQUESTS, sizeof(struct rqout));
        pthread_mutex_init(&cli->lock, NULL);

        /* slot 7 has a pending rqout with known sentauth */
        /* stack-scaffolded request, never allocated via newrequest().
           do not pass to freerq/clear_rqout — the test only stores the pointer as a
           sentinel that the slot is occupied. */
        struct request dummy_rq;
        memset(&dummy_rq, 0, sizeof(dummy_rq));
        cli->reverse_coa_rqs[7].rq = &dummy_rq;
        memcpy(cli->reverse_coa_rqs[7].sentauth, sentauth, 16);

        list_push(conf.clients, cli);

        /* packet source: same IP as client_addr but from CoA listener port 3799 */
        struct sockaddr_in coa_src = {.sin_family = AF_INET};
        inet_pton(AF_INET, "192.0.2.100", &coa_src.sin_addr);
        coa_src.sin_port = htons(3799);

        /* test 1: matching ip + correct auth -> returns client */
        struct client *result = find_reverse_coa_client_for_response(
            &conf, 42, (struct sockaddr *)&coa_src, pkt, 20);
        test_ok(result == cli, "find_rcoa_client: correct ip+auth returns client");

        /* test 2: slot rq == NULL -> NULL */
        cli->reverse_coa_rqs[7].rq = NULL;
        result = find_reverse_coa_client_for_response(
            &conf, 42, (struct sockaddr *)&coa_src, pkt, 20);
        test_ok(result == NULL, "find_rcoa_client: no pending rq returns NULL");
        cli->reverse_coa_rqs[7].rq = &dummy_rq;

        /* test 3: wrong sentauth (client stored different sentauth) -> NULL */
        uint8_t wrong_sentauth[16];
        memcpy(wrong_sentauth, sentauth, 16);
        wrong_sentauth[0] ^= 0xff;
        memcpy(cli->reverse_coa_rqs[7].sentauth, wrong_sentauth, 16);
        result = find_reverse_coa_client_for_response(
            &conf, 42, (struct sockaddr *)&coa_src, pkt, 20);
        test_ok(result == NULL, "find_rcoa_client: mismatched sentauth returns NULL");
        memcpy(cli->reverse_coa_rqs[7].sentauth, sentauth, 16);

        /* test 4: wrong source ip -> NULL */
        struct sockaddr_in wrong_src = {.sin_family = AF_INET};
        inet_pton(AF_INET, "192.0.2.200", &wrong_src.sin_addr);
        wrong_src.sin_port = htons(3799);
        result = find_reverse_coa_client_for_response(
            &conf, 42, (struct sockaddr *)&wrong_src, pkt, 20);
        test_ok(result == NULL, "find_rcoa_client: wrong source ip returns NULL");

        /* test 5: wrong sock -> NULL */
        result = find_reverse_coa_client_for_response(
            &conf, 99, (struct sockaddr *)&coa_src, pkt, 20);
        test_ok(result == NULL, "find_rcoa_client: wrong sock returns NULL");

        /* test 6: len > 20 packet with attribute — exercises the _validauth
           attribute-bytes hashing path end-to-end */
        {
            uint8_t my_sentauth[16] = {
                0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
            };
            /* 26-byte CoA-ACK: code=44, id=9, length=26,
               auth=placeholder, Proxy-State attr type=33 len=6 val=cafebabe */
            uint8_t pkt26[26];
            pkt26[0] = RAD_CoA_ACK;
            pkt26[1] = 9;   /* id -> slot 9 */
            pkt26[2] = 0;
            pkt26[3] = 26;
            memset(pkt26 + 4, 0, 16); /* auth placeholder */
            pkt26[20] = 33;           /* Proxy-State type */
            pkt26[21] = 6;            /* length (type+len+4 bytes) */
            pkt26[22] = 0xca; pkt26[23] = 0xfe;
            pkt26[24] = 0xba; pkt26[25] = 0xbe;

            /* compute response auth over attr bytes as well */
            EVP_MD_CTX *ctx9 = EVP_MD_CTX_new();
            uint8_t computed9[16];
            EVP_DigestInit_ex(ctx9, EVP_md5(), NULL);
            EVP_DigestUpdate(ctx9, pkt26, 4);           /* code+id+length */
            EVP_DigestUpdate(ctx9, my_sentauth, 16);    /* sentauth in the slot */
            EVP_DigestUpdate(ctx9, pkt26 + 20, 6);     /* attribute bytes */
            EVP_DigestUpdate(ctx9, secret, secret_len);
            EVP_DigestFinal_ex(ctx9, computed9, NULL);
            EVP_MD_CTX_free(ctx9);
            memcpy(pkt26 + 4, computed9, 16);

            /* plant sentauth in slot 9 */
            struct request dummy_rq9;
            memset(&dummy_rq9, 0, sizeof(dummy_rq9));
            cli->reverse_coa_rqs[9].rq = &dummy_rq9;
            memcpy(cli->reverse_coa_rqs[9].sentauth, my_sentauth, 16);

            result = find_reverse_coa_client_for_response(
                &conf, 42, (struct sockaddr *)&coa_src, pkt26, 26);
            test_ok(result == cli,
                    "find_rcoa_client: len>20 packet with attribute matches");

            /* clean up slot 9 */
            cli->reverse_coa_rqs[9].rq = NULL;
        }

        /* cleanup */
        list_removedata(conf.clients, cli);
        list_free(conf.clients);
        pthread_mutex_destroy(&cli->lock);
        free(cli->addr);
        free(cli->reverse_coa_rqs);
        free(cli);
        pthread_mutex_destroy(&conf_lock);
    }

    printf("1..%d\n", numtests);
    return 0;
}
