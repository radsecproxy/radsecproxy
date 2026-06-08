/* Copyright (C) 2019, SWITCH */
/* See LICENSE for licensing information. */

#include "../debug.h"
#include "../radmsg.h"
#include "../rewrite.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printescape(uint8_t *v, uint8_t l) {
    int i;
    for (i = 0; i < l; i++) {
        if (isprint(v[i]))
            printf("%c", v[i]);
        else
            printf("\\x%02x", v[i]);
    }
}

/*origattrs and expectedattrs as struct tlv*/
/*return 0 if expected; 1 otherwise or error*/
static int
_check_rewrite(struct list *origattrs, struct rewrite *rewrite, struct list *expectedattrs, int shouldfail) {
    struct radmsg msg;
    struct list_node *n, *m;
    int i = 1;

    msg.attrs = origattrs;

    if (dorewrite(&msg, rewrite, NULL) == shouldfail) {
        if (shouldfail)
            printf("dorewrite expected to fail, but it didn't\n");
        else
            printf("dorewrite failed\n");
        return 1;
    }

    if (list_count(expectedattrs) != list_count(msg.attrs)) {
        printf("bad attribute list length! expected %d, was %d\n", list_count(expectedattrs), list_count(msg.attrs));
        return 1;
    }
    m = list_first(origattrs);
    for (n = list_first(expectedattrs); n; n = list_next(n)) {
        struct tlv *tlv_exp = (struct tlv *)n->data, *tlv_act = (struct tlv *)m->data;
        if (!eqtlv(tlv_exp, tlv_act)) {
            printf("attribute list at %d not as expected!\n", i);
            printf("  expected type: %d, actual type: %d\n", tlv_exp->t, tlv_act->t);
            printf("  expected length: %d, actual length: %d\n", tlv_exp->l, tlv_act->l);
            printf("  expected value: ");
            printescape(tlv_exp->v, tlv_exp->l);
            printf(" actual value: ");
            printescape(tlv_act->v, tlv_act->l);
            printf("\n");
            return 1;
        }
        m = list_next(m);
        i++;
    }
    return 0;
}

void _list_clear(struct list *list) {
    void *data;
    while ((data = list_shift(list)))
        free(data);
}

void _tlv_list_clear(struct list *list) {
    struct tlv *tlv;
    while ((tlv = (struct tlv *)list_shift(list)))
        freetlv(tlv);
}

void _dynattr_list_clear(struct list *list) {
    struct dynattr *da;
    while ((da = (struct dynattr *)list_shift(list))) {
        free(da->field);
        free(da);
    }
}

void _reset_rewrite(struct rewrite *rewrite) {
    rewrite->whitelist_mode = 0;
    rewrite->removeattrs = NULL;
    rewrite->removevendorattrs = NULL;
    _tlv_list_clear(rewrite->addattrs);
    _list_clear(rewrite->modattrs);
    _list_clear(rewrite->modvattrs);
    _tlv_list_clear(rewrite->supattrs);
    _dynattr_list_clear(rewrite->addmetaattrs);
    _dynattr_list_clear(rewrite->supmetaattrs);
}

static struct dynattr *makedynattr(uint8_t t, uint32_t vendor, const char *field) {
    struct dynattr *da = malloc(sizeof(struct dynattr));
    if (!da)
        return NULL;
    da->t = t;
    da->vendor = vendor;
    da->field = strdup(field);
    return da;
}

int main(int argc, char *argv[]) {
    int testcount = 35;
    struct list *origattrs, *expectedattrs;
    struct rewrite rewrite;
    char *username = "user@realm";

    debug_init("t_rewrite");

    origattrs = list_create();
    expectedattrs = list_create();

    rewrite.whitelist_mode = 0;
    rewrite.removeattrs = NULL;
    rewrite.removevendorattrs = NULL;
    rewrite.addattrs = list_create();
    rewrite.modattrs = list_create();
    rewrite.modvattrs = list_create();
    rewrite.supattrs = list_create();
    rewrite.addmetaattrs = list_create();
    rewrite.supmetaattrs = list_create();

    printf("1..%d\n", testcount);
    testcount = 1;

    /* test empty rewrite */
    {
        list_push(origattrs, maketlv(RAD_Attr_User_Name, strlen(username), username));
        list_push(expectedattrs, maketlv(RAD_Attr_User_Name, strlen(username), username));
        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - empty rewrite\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removeattr */
    {
        uint8_t removeattrs[] = {1, 2, 0};

        rewrite.removeattrs = removeattrs;
        list_push(origattrs, maketlv(1, strlen(username), username));
        list_push(origattrs, maketlv(3, strlen(username), username));

        list_push(expectedattrs, maketlv(3, strlen(username), username));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removeattrs\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs full: remove a vendor attribute completely*/
    {
        uint32_t removevendorattrs[] = {42, 256, 0};
        uint8_t value = 42;

        rewrite.removevendorattrs = removevendorattrs;
        list_push(origattrs, maketlv(1, strlen(username), username));
        list_push(origattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(43, maketlv(1, 1, &value)));

        list_push(expectedattrs, maketlv(1, strlen(username), username));
        list_push(expectedattrs, makevendortlv(43, maketlv(1, 1, &value)));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removevendorattrs full\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs last element: remove vendor attribute if last subattribute removed*/
    {
        uint32_t removevendorattrs[] = {42, 2, 0}; /*,45,12};  remove vendor 42, type 2; vendor 43 all, vendor 45 type 12} */
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
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs non-rfc: dont remove if format doesn't follow rfc recommendation*/
    {
        uint32_t removevendorattrs[] = {42, 1, 0};
        uint8_t vendor_nonrfc[] = {0, 0, 0, 45, 1, 0x12, 0x23};

        rewrite.removevendorattrs = removevendorattrs;
        list_push(origattrs, maketlv(26, 7, vendor_nonrfc));

        list_push(expectedattrs, maketlv(26, 7, vendor_nonrfc));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - removevendorattrs non-rfc\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test removevendorattrs partial attribute */
    {
        uint32_t removevendorattrs[] = {42, 2, 0};
        uint8_t vendor_long1_in[] = {0, 0, 0, 42, 2, 3, 0, 1, 3, 0};
        uint8_t vendor_long1_out[] = {0, 0, 0, 42, 1, 3, 0};
        uint8_t vendor_long2_in[] = {0, 0, 0, 42, 1, 3, 0, 2, 3, 0};
        uint8_t vendor_long2_out[] = {0, 0, 0, 42, 1, 3, 0};
        uint8_t vendor_long3_in[] = {0, 0, 0, 42, 1, 3, 0, 2, 3, 0, 3, 3, 0};
        uint8_t vendor_long3_out[] = {0, 0, 0, 42, 1, 3, 0, 3, 3, 0};

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
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test simple add */
    {
        char *value = "hello world";

        list_push(rewrite.addattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - addattribute simple\n", testcount++);

        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test add with existing attributes*/
    {
        char *value = "hello world";
        uint8_t value2 = 42;

        list_push(rewrite.addattrs, maketlv(1, strlen(value), value));
        list_push(origattrs, maketlv(2, strlen(value), value));
        list_push(origattrs, maketlv(1, 1, &value2));

        list_push(expectedattrs, maketlv(2, strlen(value), value));
        list_push(expectedattrs, maketlv(1, 1, &value2));
        list_push(expectedattrs, maketlv(1, strlen(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - addattribute with existing attributes\n", testcount++);

        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test add null*/
    {
        list_push(rewrite.addattrs, maketlv(1, 0, NULL));
        list_push(expectedattrs, maketlv(1, 0, NULL));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - addattribute null\n", testcount++);

        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
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
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test supplement non-existing*/
    {
        char *value = "hello world";

        list_push(rewrite.supattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - suppattrs non existing\n", testcount++);

        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test supplement existing*/
    {
        char *value = "hello world";
        char *value2 = "hello radsec";

        list_push(rewrite.supattrs, maketlv(1, strlen(value2), value2));
        list_push(origattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - suppattrs existing\n", testcount++);

        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test supplement vendor*/
    {
        uint8_t value = 42;
        uint8_t vendor_long1_in[] = {0, 0, 0, 42, 2, 3, 0, 1, 3, 0};

        list_push(rewrite.supattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(rewrite.supattrs, makevendortlv(42, maketlv(3, 1, &value)));
        list_push(origattrs, maketlv(26, sizeof(vendor_long1_in), vendor_long1_in));
        list_push(expectedattrs, maketlv(26, sizeof(vendor_long1_in), vendor_long1_in));
        list_push(expectedattrs, makevendortlv(42, maketlv(3, 1, &value)));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - suppattrs vendor\n", testcount++);

        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify no match*/
    {
        char *value = "hello world";
        char *value2 = "foo bar";
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;

        mod->t = 1;
        mod->regex = &regex;
        mod->replacement = value2;
        regcomp(mod->regex, "hello bar", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modattrs, mod);
        list_push(origattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - modify attribute no match\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify match full replace*/
    {
        char *value = "hello world";
        char *value2 = "foo bar";
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;

        mod->t = 1;
        mod->regex = &regex;
        mod->replacement = value2;
        regcomp(mod->regex, "hello world", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modattrs, mod);
        list_push(origattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value2), value2));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - modify attribute match full replace\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify match partial replace*/
    {
        char *value = "hello world";
        char *value2 = "hello foo";
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;

        mod->t = 1;
        mod->regex = &regex;
        mod->replacement = "\\1 foo";
        regcomp(mod->regex, "(hello) world", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modattrs, mod);
        list_push(origattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value2), value2));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - modify attribute match full replace\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify max length*/
    {
        char *value = "hello radsecproxy..."; /*make this 20 chars long 8*/
        char value2[254];
        int i;
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;

        for (i = 0; i < 253 - 20; i += 20) {
            memcpy(value2 + i, value, 20);
        }
        memcpy(value2 + i, "and another13\0", 14);

        mod->t = 1;
        mod->regex = &regex;
        mod->replacement = "\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1and another13";
        regcomp(mod->regex, "(.*)", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modattrs, mod);
        list_push(origattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value2), value2));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - modify attribute max length\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify too long*/
    {
        char *value = "hello radsecproxy..."; /*make this 20 chars long 8*/
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;
        mod->t = 1;
        mod->regex = &regex;
        mod->replacement = "\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1and another14!";
        regcomp(mod->regex, "(.*)", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modattrs, mod);
        list_push(origattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value), value));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 1))
            printf("not ");
        printf("ok %d - modify attribute too long\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify regex replace*/
    {
        char *value = "hello";
        char *value2 = "hellohellohellohellohellohellohellohellohello";
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;
        mod->t = 1;
        mod->regex = &regex;
        mod->replacement = "\\1\\2\\3\\4\\5\\6\\7\\8\\9";
        regcomp(mod->regex, "(((((((((hello)))))))))", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modattrs, mod);
        list_push(origattrs, maketlv(1, strlen(value), value));
        list_push(expectedattrs, maketlv(1, strlen(value2), value2));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - modify attribute regex replace\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify vendor*/
    {
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;
        uint8_t vendorattrin[] = {0, 0, 0, 42, 1, 3, 'b', 1, 3, 'a', 2, 3, 0, 1, 3, 'a'};
        uint8_t vendorattrout[] = {0, 0, 0, 42, 1, 3, 'b', 1, 4, 'b', 'b', 2, 3, 0, 1, 4, 'b', 'b'};

        mod->t = 1;
        mod->vendor = 42;
        mod->regex = &regex;
        mod->replacement = "bb";
        regcomp(mod->regex, "a", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modvattrs, mod);
        list_push(origattrs, maketlv(RAD_Attr_Vendor_Specific, sizeof(vendorattrin), vendorattrin));
        list_push(expectedattrs, maketlv(RAD_Attr_Vendor_Specific, sizeof(vendorattrout), vendorattrout));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - modify vendor\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test modify vendor too long (total vendor attribute too long) */
    {
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;
        uint8_t vendorattrin[RAD_Max_Attr_Value_Length];

        memset(vendorattrin, 0, RAD_Max_Attr_Value_Length);
        vendorattrin[3] = 42;
        vendorattrin[4] = 1;
        vendorattrin[5] = 3;
        vendorattrin[6] = 'a';
        vendorattrin[7] = 2;
        vendorattrin[8] = RAD_Max_Attr_Value_Length - 7;

        mod->t = 1;
        mod->vendor = 42;
        mod->regex = &regex;
        mod->replacement = "bb";
        regcomp(mod->regex, "a", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modvattrs, mod);
        list_push(origattrs, maketlv(RAD_Attr_Vendor_Specific, sizeof(vendorattrin), vendorattrin));

        if (_check_rewrite(origattrs, &rewrite, origattrs, 1))
            printf("not ");
        printf("ok %d - modify vendor too long\n", testcount++);

        regfree(&regex);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test whitelist rewrite */
    {
        uint8_t whitelistattrs[] = {1, 0};
        rewrite.whitelist_mode = 1;
        rewrite.removeattrs = whitelistattrs;

        list_push(origattrs, maketlv(1, strlen(username), username));
        list_push(origattrs, maketlv(3, strlen(username), username));
        list_push(origattrs, makevendortlv(42, maketlv(1, strlen(username), username)));

        list_push(expectedattrs, maketlv(1, strlen(username), username));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - whitelistattrs\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test whitelist vendor rewrite */
    {
        uint32_t whitelistvendorattrs[] = {42, 256, 0};
        uint8_t value = 42;
        uint8_t vendor_nonrfc_in[] = {0, 0, 0, 42, 1, 2, 3, 4};

        rewrite.whitelist_mode = 1;
        rewrite.removevendorattrs = whitelistvendorattrs;
        list_push(origattrs, maketlv(1, strlen(username), username));
        list_push(origattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(43, maketlv(1, 1, &value)));
        list_push(origattrs, maketlv(26, sizeof(vendor_nonrfc_in), vendor_nonrfc_in));

        list_push(expectedattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(expectedattrs, maketlv(26, sizeof(vendor_nonrfc_in), vendor_nonrfc_in));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - whitelistvendorattrs\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test whitelist vendor rewrite subattribute*/
    {
        uint32_t whitelistvendorattrs[] = {42, 1, 0};
        uint8_t value = 42;
        uint8_t vendor_long1_in[] = {0, 0, 0, 42, 2, 3, 0, 1, 3, 0};
        uint8_t vendor_long1_out[] = {0, 0, 0, 42, 1, 3, 0};
        uint8_t vendor_nonrfc_in[] = {0, 0, 0, 42, 1, 2, 3, 4};

        rewrite.whitelist_mode = 1;
        rewrite.removevendorattrs = whitelistvendorattrs;
        list_push(origattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(43, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(42, maketlv(2, 1, &value)));
        list_push(origattrs, maketlv(26, sizeof(vendor_long1_in), vendor_long1_in));
        list_push(origattrs, maketlv(26, sizeof(vendor_nonrfc_in), vendor_nonrfc_in));

        list_push(expectedattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(expectedattrs, maketlv(26, sizeof(vendor_long1_out), vendor_long1_out));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - whitelistvendorattrs\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test whitelist vendor rewrite combined*/
    {
        uint32_t whitelistvendorattrs[] = {42, 1, 0};
        uint8_t whitelistattrs[] = {1, 0};
        uint8_t value = 42;

        rewrite.whitelist_mode = 1;
        rewrite.removeattrs = whitelistattrs;
        rewrite.removevendorattrs = whitelistvendorattrs;
        list_push(origattrs, maketlv(1, strlen(username), username));
        list_push(origattrs, maketlv(3, strlen(username), username));
        list_push(origattrs, makevendortlv(42, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(43, maketlv(1, 1, &value)));
        list_push(origattrs, makevendortlv(43, maketlv(2, 1, &value)));

        list_push(expectedattrs, maketlv(1, strlen(username), username));
        list_push(expectedattrs, makevendortlv(42, maketlv(1, 1, &value)));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - whitelistvendorattrs\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /*  test issue #62
        rewrite 9:102:/^(h323-credit-time).*$/\1=86400/
    */
    {
        char *value = "h323-credit-time=1846422";
        char *expect = "h323-credit-time=86400";
        struct modattr *mod = malloc(sizeof(struct modattr));
        regex_t regex;

        mod->t = 102;
        mod->vendor = 9;
        mod->regex = &regex;
        mod->replacement = "\\1=86400";
        regcomp(mod->regex, "^(h323-credit-time).*$", REG_ICASE | REG_EXTENDED);

        list_push(rewrite.modvattrs, mod);
        list_push(origattrs, makevendortlv(9, maketlv(102, strlen(value), value)));
        list_push(expectedattrs, makevendortlv(9, maketlv(102, strlen(expect), expect)));

        if (_check_rewrite(origattrs, &rewrite, expectedattrs, 0))
            printf("not ");
        printf("ok %d - issue #62\n", testcount++);

        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta add source_ip IPv4 */
    {
        struct sockaddr_in sa4;
        struct rewrite_context ctx;
        struct radmsg msg;
        char *expected_ip = "192.168.1.5";

        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        sa4.sin_port = htons(1812);
        inet_pton(AF_INET, expected_ip, &sa4.sin_addr);
        ctx.clientaddr = (struct sockaddr *)&sa4;
        ctx.clientname = "testclient";

        list_push(rewrite.addmetaattrs, makedynattr(31, 0, "source_ip"));

        msg.attrs = origattrs;
        list_push(expectedattrs, maketlv(31, strlen(expected_ip), expected_ip));

        if (dorewrite(&msg, &rewrite, &ctx) != 1 ||
            list_count(msg.attrs) != 1 ||
            !eqtlv((struct tlv *)list_first(msg.attrs)->data,
                    (struct tlv *)list_first(expectedattrs)->data))
            printf("not ");
        printf("ok %d - meta add source_ip IPv4\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta add source_ip IPv6 */
    {
        struct sockaddr_in6 sa6;
        struct rewrite_context ctx;
        struct radmsg msg;
        char *expected_ip = "2001:db8::1";

        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(1812);
        inet_pton(AF_INET6, expected_ip, &sa6.sin6_addr);
        ctx.clientaddr = (struct sockaddr *)&sa6;
        ctx.clientname = "testclient";

        list_push(rewrite.addmetaattrs, makedynattr(31, 0, "source_ip"));

        msg.attrs = origattrs;
        list_push(expectedattrs, maketlv(31, strlen(expected_ip), expected_ip));

        if (dorewrite(&msg, &rewrite, &ctx) != 1 ||
            list_count(msg.attrs) != 1 ||
            !eqtlv((struct tlv *)list_first(msg.attrs)->data,
                    (struct tlv *)list_first(expectedattrs)->data))
            printf("not ");
        printf("ok %d - meta add source_ip IPv6\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta add source_port */
    {
        struct sockaddr_in sa4;
        struct rewrite_context ctx;
        struct radmsg msg;
        char *expected_port = "1812";

        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        sa4.sin_port = htons(1812);
        inet_pton(AF_INET, "10.0.0.1", &sa4.sin_addr);
        ctx.clientaddr = (struct sockaddr *)&sa4;
        ctx.clientname = "testclient";

        list_push(rewrite.addmetaattrs, makedynattr(5, 0, "source_port"));

        msg.attrs = origattrs;
        list_push(expectedattrs, maketlv(5, strlen(expected_port), expected_port));

        if (dorewrite(&msg, &rewrite, &ctx) != 1 ||
            list_count(msg.attrs) != 1 ||
            !eqtlv((struct tlv *)list_first(msg.attrs)->data,
                    (struct tlv *)list_first(expectedattrs)->data))
            printf("not ");
        printf("ok %d - meta add source_port\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta add client_name */
    {
        struct sockaddr_in sa4;
        struct rewrite_context ctx;
        struct radmsg msg;
        char *expected_name = "testclient";

        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        ctx.clientaddr = (struct sockaddr *)&sa4;
        ctx.clientname = expected_name;

        list_push(rewrite.addmetaattrs, makedynattr(32, 0, "client_name"));

        msg.attrs = origattrs;
        list_push(expectedattrs, maketlv(32, strlen(expected_name), expected_name));

        if (dorewrite(&msg, &rewrite, &ctx) != 1 ||
            list_count(msg.attrs) != 1 ||
            !eqtlv((struct tlv *)list_first(msg.attrs)->data,
                    (struct tlv *)list_first(expectedattrs)->data))
            printf("not ");
        printf("ok %d - meta add client_name\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta supplement non-existing */
    {
        struct sockaddr_in sa4;
        struct rewrite_context ctx;
        struct radmsg msg;
        char *expected_ip = "10.0.0.1";

        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, expected_ip, &sa4.sin_addr);
        ctx.clientaddr = (struct sockaddr *)&sa4;
        ctx.clientname = "testclient";

        list_push(rewrite.supmetaattrs, makedynattr(31, 0, "source_ip"));

        msg.attrs = origattrs;
        list_push(expectedattrs, maketlv(31, strlen(expected_ip), expected_ip));

        if (dorewrite(&msg, &rewrite, &ctx) != 1 ||
            list_count(msg.attrs) != 1 ||
            !eqtlv((struct tlv *)list_first(msg.attrs)->data,
                    (struct tlv *)list_first(expectedattrs)->data))
            printf("not ");
        printf("ok %d - meta supplement non-existing\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta supplement existing - should not add */
    {
        struct sockaddr_in sa4;
        struct rewrite_context ctx;
        struct radmsg msg;
        char *existing_val = "existing";

        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "10.0.0.1", &sa4.sin_addr);
        ctx.clientaddr = (struct sockaddr *)&sa4;
        ctx.clientname = "testclient";

        list_push(rewrite.supmetaattrs, makedynattr(31, 0, "source_ip"));
        list_push(origattrs, maketlv(31, strlen(existing_val), existing_val));
        list_push(expectedattrs, maketlv(31, strlen(existing_val), existing_val));

        msg.attrs = origattrs;

        if (dorewrite(&msg, &rewrite, &ctx) != 1 ||
            list_count(msg.attrs) != 1 ||
            !eqtlv((struct tlv *)list_first(msg.attrs)->data,
                    (struct tlv *)list_first(expectedattrs)->data))
            printf("not ");
        printf("ok %d - meta supplement existing\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta add vendor attribute */
    {
        struct sockaddr_in sa4;
        struct rewrite_context ctx;
        struct radmsg msg;
        char *expected_ip = "10.0.0.1";

        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, expected_ip, &sa4.sin_addr);
        ctx.clientaddr = (struct sockaddr *)&sa4;
        ctx.clientname = "testclient";

        list_push(rewrite.addmetaattrs, makedynattr(1, 12345, "source_ip"));

        msg.attrs = origattrs;
        list_push(expectedattrs, makevendortlv(12345, maketlv(1, strlen(expected_ip), expected_ip)));

        if (dorewrite(&msg, &rewrite, &ctx) != 1 ||
            list_count(msg.attrs) != 1 ||
            !eqtlv((struct tlv *)list_first(msg.attrs)->data,
                    (struct tlv *)list_first(expectedattrs)->data))
            printf("not ");
        printf("ok %d - meta add vendor attribute\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test meta with NULL context - should skip gracefully */
    {
        struct radmsg msg;

        list_push(rewrite.addmetaattrs, makedynattr(31, 0, "source_ip"));

        msg.attrs = origattrs;

        if (dorewrite(&msg, &rewrite, NULL) != 1 ||
            list_count(msg.attrs) != 0)
            printf("not ");
        printf("ok %d - meta with NULL context\n", testcount++);
        _tlv_list_clear(origattrs);
        _tlv_list_clear(expectedattrs);
        _reset_rewrite(&rewrite);
    }

    /* test extractdynattr rejects invalid input */
    {
        char *invalid_keyword = strdup("31:bogus_field");
        char *missing_colon = strdup("31");
        char *vendor_zero = strdup("0:1:source_ip");
        char *name_zero = strdup("0:source_ip");

        if (extractdynattr(invalid_keyword, 0) != NULL ||
            extractdynattr(missing_colon, 0) != NULL ||
            extractdynattr(vendor_zero, 1) != NULL ||
            extractdynattr(name_zero, 0) != NULL)
            printf("not ");
        printf("ok %d - extractdynattr rejects invalid input\n", testcount++);

        free(invalid_keyword);
        free(missing_colon);
        free(vendor_zero);
        free(name_zero);
    }

    list_destroy(origattrs);
    list_destroy(expectedattrs);
    list_destroy(rewrite.addattrs);
    list_destroy(rewrite.modattrs);
    list_destroy(rewrite.modvattrs);
    list_destroy(rewrite.supattrs);
    list_destroy(rewrite.addmetaattrs);
    list_destroy(rewrite.supmetaattrs);

    return 0;
}
