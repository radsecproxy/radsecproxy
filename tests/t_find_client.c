/* Copyright (C) 2020, SWITCH */
/* See LICENSE for licensing information. */

#include "../debug.h"
#include "../hostport.h"
#include "../radsecproxy.h"
#include "../util.h"
#include <netdb.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

extern struct clsrvconf *find_conf(uint8_t type, struct sockaddr *addr, struct list *confs, struct list_node **cur, uint8_t server_p, struct hostportres **hp);
int numtests = 0;

struct clsrvconf *createclient(char *name, char **hosts) {
    struct clsrvconf *newconf = malloc(sizeof(struct clsrvconf));
    newconf->name = name;
    newconf->type = RAD_TLS;
    newconf->hostports = list_create();
    for (; *hosts; hosts++) {
        list_push(newconf->hostports, newhostport(*hosts, "1812", 1));
        resolvehostports(newconf->hostports, AF_UNSPEC, SOCK_STREAM);
    }
    return newconf;
}

void freeclient(struct clsrvconf *conf) {
    freehostports(conf->hostports);
    free(conf);
}

void ok(struct clsrvconf *expect, struct clsrvconf *result, char *descr) {
    if (result == expect) {
        printf("ok %d - %s\n", ++numtests, descr);
    } else {
        printf("not ok %d - %s\n", ++numtests, descr);
    }
}

void ok_hp(char *expect_addr, struct hostportres *hp, char *descr) {
    if (strcmp(expect_addr, hp->host) == 0) {
        printf("ok %d - %s\n", ++numtests, descr);
    } else {
        printf("not ok %d - %s (%s)\n", ++numtests, descr, hp->host);
    }
}

int main(int argc, char *argv[]) {
    struct list *confs = list_create();

    struct sockaddr_in addr1 = {.sin_family = AF_INET};
    inet_pton(AF_INET, "192.0.2.1", &addr1.sin_addr);

    struct sockaddr_in addr2 = {.sin_family = AF_INET};
    inet_pton(AF_INET, "192.0.2.2", &addr2.sin_addr);

    struct sockaddr_in6 addr3 = {.sin6_family = AF_INET6};
    inet_pton(AF_INET6, "2001:db8::1", &addr3.sin6_addr);

    /* basic test */
    {
        struct clsrvconf *client = createclient("client1", (char *[]){"192.0.2.1", NULL});
        list_push(confs, client);

        ok(client, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, NULL, 0, NULL), "simple client found");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr2, confs, NULL, 0, NULL), "simple client not found");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr3, confs, NULL, 0, NULL), "simple client not found wrong AF");
        ok(NULL, find_conf(RAD_DTLS, (struct sockaddr *)&addr1, confs, NULL, 0, NULL), "simple client not found wrong type");

        while (list_shift(confs))
            ;
        freeclient(client);
    }

    /* two clients */
    {
        struct clsrvconf *client1 = createclient("client1", (char *[]){"192.0.2.1", NULL});
        list_push(confs, client1);
        struct clsrvconf *client2 = createclient("client2", (char *[]){"192.0.2.2", NULL});
        list_push(confs, client2);

        ok(client1, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, NULL, 0, NULL), "two clients, first");
        ok(client2, find_conf(RAD_TLS, (struct sockaddr *)&addr2, confs, NULL, 0, NULL), "two clients, second");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr3, confs, NULL, 0, NULL), "two clients wrong AF");

        while (list_shift(confs))
            ;
        freeclient(client1);
        freeclient(client2);
    }

    // two identical clients */
    {
        struct clsrvconf *client1 = createclient("client1", (char *[]){"192.0.2.1", NULL});
        list_push(confs, client1);
        struct clsrvconf *client2 = createclient("client2", (char *[]){"192.0.2.1", NULL});
        list_push(confs, client2);

        struct list_node *cur = NULL;

        ok(client1, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, NULL), "two identical clients, first");
        ok(client2, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, NULL), "two identical clients, second");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, NULL), "two identical clients, third");

        while (list_shift(confs))
            ;
        freeclient(client1);
        freeclient(client2);
    }

    /* client with two hostports match second (check correct hostport) */
    {
        struct clsrvconf *client = createclient("client1", (char *[]){"192.0.2.1", "192.0.2.2", NULL});
        list_push(confs, client);

        struct list_node *cur = NULL;
        struct hostportres *hp = NULL;

        ok(client, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, &hp), "client two addresses, first");
        ok_hp("192.0.2.1", hp, "client two addresses, first address");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, &hp), "client two addresses, first end");

        cur = NULL;
        hp = NULL;
        ok(client, find_conf(RAD_TLS, (struct sockaddr *)&addr2, confs, &cur, 0, &hp), "client two addresses, second");
        ok_hp("192.0.2.2", hp, "client two addresses, second address");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, &hp), "client two addresses, second end");

        while (list_shift(confs))
            ;
        freeclient(client);
    }

    /* client with prefix */
    {
        struct clsrvconf *client = createclient("client1", (char *[]){"192.0.2.0/24", NULL});
        list_push(confs, client);

        ok(client, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, NULL, 0, NULL), "client with prefix, first address");
        ok(client, find_conf(RAD_TLS, (struct sockaddr *)&addr2, confs, NULL, 0, NULL), "client with prefix, second address");
        while (list_shift(confs))
            ;
        freeclient(client);
    }

    /* client with address and prefix, assume first address resolved by DNS, happens to be in same subnet */
    {
        struct clsrvconf *client1 = createclient("client1", (char *[]){"192.0.2.1", "192.0.2.0/24", NULL});
        list_push(confs, client1);
        struct clsrvconf *client2 = createclient("client2", (char *[]){"0.0.0.0/0", "[::]/0", NULL});
        list_push(confs, client2);

        struct list_node *cur = NULL;
        struct hostportres *hp = NULL;

        ok(client1, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, &hp), "address and prefix, first address");
        ok_hp("192.0.2.1", hp, "address and prefix, first address");
        ok(client1, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, &hp), "address and prefix, prefix");
        ok_hp("192.0.2.0", hp, "address and prefix, prefix");
        ok(client2, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, &hp), "address and prefix, wildcard");
        ok_hp("0.0.0.0", hp, "address and prefix, wildcard");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr1, confs, &cur, 0, &hp), "address and prefix, end");

        cur = NULL;
        hp = NULL;
        ok(client2, find_conf(RAD_TLS, (struct sockaddr *)&addr3, confs, &cur, 0, &hp), "address and prefix, IPv6 wildcard");
        ok_hp("::", hp, "address and prefix, IPv6 wildcard");
        ok(NULL, find_conf(RAD_TLS, (struct sockaddr *)&addr3, confs, &cur, 0, &hp), "address and prefix, IPv6 wildcard end");

        while (list_shift(confs))
            ;
        freeclient(client1);
        freeclient(client2);
    }

    printf("1..%d\n", numtests);
    list_destroy(confs);

    return 0;
}
