/* Copyright (C) 2019, SWITCH */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rewrite.h"
#include "../radmsg.h"
#include "../debug.h"

/*origattrs and expectedattrs as struct tlv*/
/*return 0 if expected; 1 otherwise or error*/
static int
_check_rewrite(struct list *origattrs, struct rewrite *rewrite, struct list *expectedattrs, int shouldfail) {
    struct radmsg msg;
    struct list_node *n,*m;

    msg.attrs = origattrs;

    if(dorewrite(&msg, rewrite) == shouldfail) {
        if (shouldfail)
            printf("dorewrite expected to fail, but it didn't\n");
        else
            printf("dorewrite failed\n");
        return 1;
    }

    if(list_count(expectedattrs) != list_count(msg.attrs)) {
        printf("bad attribute list length! expected %d, was %d\n", list_count(expectedattrs), list_count(msg.attrs));
        return 1;
    }
    m=list_first(origattrs);
    for(n=list_first(expectedattrs); n; n=list_next(n)) {
        if (!eqtlv((struct tlv *)n->data, (struct tlv *)m->data)) {
            printf("attribute list not as expected\n");
            return 1;
        }
        m=list_next(m);
    }
    return 0;
}

void _list_clear(struct list *list) {
    void *data;
    while ( (data = list_shift(list)) )
        free(data);
}

void _reset_rewrite(struct rewrite *rewrite) {
    rewrite->removeattrs = NULL;
    rewrite->removevendorattrs = NULL;
    _list_clear(rewrite->addattrs);
    _list_clear(rewrite->modattrs);
    _list_clear(rewrite->supattrs);
}

int
main (int argc, char *argv[])
{
    int testcount = 12;
    struct list *origattrs, *expectedattrs;
    struct rewrite rewrite;
    char *username = "user@realm";

    debug_init("t_rewrite");

    origattrs=list_create();
    expectedattrs=list_create();

    rewrite.removeattrs = NULL;
    rewrite.removevendorattrs = NULL;
    rewrite.addattrs = list_create();
    rewrite.modattrs = list_create();
    rewrite.supattrs = list_create();

    printf("1..%d\n", testcount);
    testcount = 1;

    /* test empty rewrite */
    {
        list_push(origattrs, maketlv(RAD_Attr_User_Name, sizeof(username), username));
        list_push(expectedattrs, maketlv(RAD_Attr_User_Name, sizeof(username), username));
        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - empty rewrite\n", testcount++);
        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removeattr */
    {
        uint8_t removeattrs[] = {1,2,0};

        rewrite.removeattrs = removeattrs;
        list_push(origattrs, maketlv(1, sizeof(username), username));
        list_push(origattrs, maketlv(3, sizeof(username), username));

        list_push(expectedattrs, maketlv(3, sizeof(username), username));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removeattrs\n", testcount++);
        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs full: remove a vendor attribute completely*/
    {
        uint32_t removevendorattrs[] = {42,256,0};
        uint8_t value = 42;

        rewrite.removevendorattrs = removevendorattrs;
        list_push(origattrs, maketlv(1, sizeof(username), username));
        list_push(origattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(43, maketlv(1, 1, &value)));

        list_push(expectedattrs, maketlv(1, sizeof(username), username));
        list_push(expectedattrs, makevendortlv(43, maketlv(1, 1, &value)));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removevendorattrs full\n", testcount++);
        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs last element: remove vendor attribute if last subattribute removed*/
    {
        uint32_t removevendorattrs[] = {42,2,0}; /*,45,12};  remove vendor 42, type 2; vendor 43 all, vendor 45 type 12} */
        uint8_t value = 42;

        rewrite.removevendorattrs = removevendorattrs;
        list_push(origattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(42, maketlv(2, 1, &value)));
        list_push(origattrs, makevendortlv(43, maketlv(2, 1, &value)));

        list_push(expectedattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(expectedattrs, makevendortlv(43, maketlv(2, 1, &value)));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removevendorattrs last element\n", testcount++);
        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs non-rfc: dont remove if format doesn't follow rfc recommendation*/
    {
        uint32_t removevendorattrs[] = {42,1,0};
        uint8_t vendor_nonrfc[] = {0, 0, 0, 45, 1, 0x12, 0x23};

        rewrite.removevendorattrs = removevendorattrs;
        list_push(origattrs, maketlv(26, 7, vendor_nonrfc));

        list_push(expectedattrs, maketlv(26, 7, vendor_nonrfc));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removevendorattrs non-rfc\n", testcount++);
        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs partial attribute */
    {
        uint32_t removevendorattrs[] = {42,2,0};
        uint8_t vendor_long1_in[] = {0,0,0,42,2,3,0,1,3,0};
        uint8_t vendor_long1_out[] = {0,0,0,42,1,3,0};
        uint8_t vendor_long2_in[] = {0,0,0,42,1,3,0,2,3,0};
        uint8_t vendor_long2_out[] = {0,0,0,42,1,3,0};
        uint8_t vendor_long3_in[] = {0,0,0,42,1,3,0,2,3,0,3,3,0};
        uint8_t vendor_long3_out[] = {0,0,0,42,1,3,0,3,3,0};

        rewrite.removevendorattrs = removevendorattrs;
        list_push(origattrs, maketlv(26, sizeof(vendor_long1_in), vendor_long1_in));
        list_push(origattrs, maketlv(26, sizeof(vendor_long2_in), vendor_long2_in));
        list_push(origattrs, maketlv(26, sizeof(vendor_long3_in), vendor_long3_in));

        list_push(expectedattrs, maketlv(26, sizeof(vendor_long1_out), vendor_long1_out));
        list_push(expectedattrs, maketlv(26, sizeof(vendor_long2_out), vendor_long2_out));
        list_push(expectedattrs, maketlv(26, sizeof(vendor_long3_out), vendor_long3_out));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removevendorattrs sub-attribute\n", testcount++);
        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test simple add */
    {
        char *value = "hello world";

        list_push(rewrite.addattrs, maketlv(1, sizeof(value), value));
        list_push(expectedattrs, maketlv(1,sizeof(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - addattribute simple\n", testcount++);

        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test add with existing attributes*/
    {
        char *value = "hello world";
        uint8_t value2 = 42;

        list_push(rewrite.addattrs, maketlv(1, sizeof(value), value));
        list_push(origattrs, maketlv(2, sizeof(value), value));
        list_push(origattrs, maketlv(1, 1, &value2));

        list_push(expectedattrs, maketlv(2,sizeof(value), value));
        list_push(expectedattrs, maketlv(1,1, &value2));
        list_push(expectedattrs, maketlv(1,sizeof(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - addattribute with existing attributes\n", testcount++);

        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test add null*/
    {
        list_push(rewrite.addattrs, maketlv(1, 0, NULL));
        list_push(expectedattrs, maketlv(1,0, NULL));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - addattribute null\n", testcount++);

        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test add too big*/
    {
        uint8_t *value = malloc(254);
        memset(value, 0, 254);

        list_push(rewrite.addattrs, maketlv(1, 254, value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 1))
            printf("not ");
        printf("ok %d - addattribute too big\n", testcount++);

        free(value);
        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test supplement non-existing*/
    {
        char *value = "hello world";

        list_push(rewrite.supattrs, maketlv(1, sizeof(value), value));
        list_push(expectedattrs, maketlv(1,sizeof(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - suppattrs non existing\n", testcount++);

        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test supplement existing*/
    {
        char *value = "hello world";
        char *value2 = "hello radsec";

        list_push(rewrite.supattrs, maketlv(1, sizeof(value2), value2));
        list_push(origattrs, maketlv(1,sizeof(value), value));
        list_push(expectedattrs, maketlv(1,sizeof(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - suppattrs existing\n", testcount++);

        _list_clear(origattrs);
        _list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }





    return 0;
}
