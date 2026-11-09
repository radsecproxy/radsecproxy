/* Copyright (C) 2026, CyB0rgg */
/* See LICENSE for licensing information. */

#include "../dns.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SERVICE "aaa+auth:radius.tls.tcp"

static struct naptr_record rec(uint16_t order, uint16_t preference, const char *flags, const char *services, const char *replacement) {
    struct naptr_record r;
    memset(&r, 0, sizeof(r));
    r.order = order;
    r.preference = preference;
    strncpy(r.flags, flags, sizeof(r.flags) - 1);
    strncpy(r.services, services, sizeof(r.services) - 1);
    strncpy(r.replacement, replacement, sizeof(r.replacement) - 1);
    return r;
}

/* expected: space separated replacement names in the expected order */
static void check(int *testcount, struct naptr_record **in, const char *expected, const char *name) {
    struct naptr_record **sel = naptrselect(in, SERVICE);
    char got[1024] = "";
    int i, ok;

    for (i = 0; sel && sel[i]; i++) {
        if (i)
            strcat(got, " ");
        strcat(got, sel[i]->replacement);
    }
    ok = sel && strcmp(got, expected) == 0;
    if (!ok)
        printf("# expected [%s], got [%s]\n", expected, sel ? got : "(null)");
    printf("%sok %d - %s\n", ok ? "" : "not ", ++*testcount, name);
    free(sel);
}

int main(int argc, char *argv[]) {
    int testcount = 0;

    {
        struct naptr_record a = rec(50, 50, "s", SERVICE, "_radsec._tcp.a.example");
        struct naptr_record *in[] = {&a, NULL};
        check(&testcount, in, "_radsec._tcp.a.example", "single matching record");
    }
    {
        /* response order is not the record order */
        struct naptr_record a = rec(20, 10, "s", SERVICE, "second");
        struct naptr_record b = rec(10, 10, "s", SERVICE, "first");
        struct naptr_record c = rec(30, 10, "s", SERVICE, "third");
        struct naptr_record *in[] = {&a, &b, &c, NULL};
        check(&testcount, in, "first second third", "sorted by order");
    }
    {
        struct naptr_record a = rec(10, 50, "s", SERVICE, "second");
        struct naptr_record b = rec(10, 10, "s", SERVICE, "first");
        struct naptr_record *in[] = {&a, &b, NULL};
        check(&testcount, in, "first second", "same order, sorted by preference");
    }
    {
        struct naptr_record a = rec(10, 10, "s", SERVICE, "one");
        struct naptr_record b = rec(10, 10, "s", SERVICE, "two");
        struct naptr_record c = rec(10, 10, "s", SERVICE, "three");
        struct naptr_record *in[] = {&a, &b, &c, NULL};
        check(&testcount, in, "one two three", "equal order and preference keep response order");
    }
    {
        struct naptr_record a = rec(10, 10, "s", "aaa+acct:radius.tls.tcp", "acct");
        struct naptr_record b = rec(10, 10, "s", SERVICE, "auth");
        struct naptr_record c = rec(10, 10, "s", "x-eduroam:radius.tls", "eduroam");
        struct naptr_record *in[] = {&a, &b, &c, NULL};
        check(&testcount, in, "auth", "other services are excluded");
    }
    {
        struct naptr_record a = rec(10, 10, "a", SERVICE, "direct");
        struct naptr_record b = rec(20, 10, "s", SERVICE, "srv");
        struct naptr_record *in[] = {&a, &b, NULL};
        check(&testcount, in, "srv", "only the S flag is used");
    }
    {
        struct naptr_record a = rec(10, 10, "S", "AAA+AUTH:RADIUS.TLS.TCP", "upper");
        struct naptr_record *in[] = {&a, NULL};
        check(&testcount, in, "upper", "service and flag match case-insensitively");
    }
    {
        struct naptr_record a = rec(10, 10, "s", "x-eduroam:radius.tls", "eduroam");
        struct naptr_record *in[] = {&a, NULL};
        check(&testcount, in, "", "no usable record gives an empty list, not NULL");
    }
    {
        struct naptr_record *in[] = {NULL};
        check(&testcount, in, "", "empty response");
        check(&testcount, NULL, "", "null response");
    }

    printf("1..%d\n", testcount);
    return 0;
}
