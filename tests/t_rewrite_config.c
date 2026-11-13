/* Copyright (C) 2019, SWITCH */
/* See LICENSE for licensing information. */

#include "../debug.h"
#include "../radmsg.h"
#include "../rewrite.h"
#include "../util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    struct rewrite *result;
    char *rewritename = "rewrite";
    char **addattrs;
    int numtests = 3, i;
    struct tlv *tlv, *expected;
    uint8_t expectedvalue[] = {'1', 0, 0, '1', 'A', '%', '4', '1'};

    printf("1..%d\n", numtests);
    numtests = 1;

    {
        addattrs = malloc(2 * sizeof(char *));
        addattrs[0] = stringcopy("1:'1%00%001%41%2541", 0);
        addattrs[1] = NULL;

        expected = maketlv(1, 8, expectedvalue);

        addrewrite(rewritename, 0, NULL, NULL, addattrs,
                   NULL, NULL, NULL, NULL, NULL,
                   NULL, NULL, NULL, NULL);

        result = getrewrite(rewritename, NULL);

        if (result->addattrs->first) {
            tlv = (struct tlv *)result->addattrs->first->data;
            if (!eqtlv(tlv, expected)) {
                printf("tlv value was: 0x");
                for (i = 0; i < tlv->l; i++) {
                    printf("%x", *((tlv->v) + i));
                }
                printf("\n");
                printf("not ");
            }
            printf("ok %d - rewrite config\n", numtests++);
        } else {
            printf("not ok %d - rewrite config\n", numtests++);
        }

        freetlv(expected);
    }

    /* test issue #62 */
    {
        char *expectreplace = "\\1=86400";
        char **modvattrs = malloc(2 * sizeof(char *));
        rewritename = "issue62";

        modvattrs[0] = stringcopy("9:102:/^(h323-credit-time).*$/\\1=86400/", 0);
        modvattrs[1] = NULL;

        addrewrite(rewritename, 0, NULL, NULL, NULL, NULL, NULL, modvattrs, NULL, NULL,
                   NULL, NULL, NULL, NULL);
        result = getrewrite(rewritename, NULL);

        if (result && result->modvattrs && result->modvattrs->first) {
            struct modattr *mod = (struct modattr *)result->modvattrs->first->data;
            if (regexec(mod->regex, "h323-credit-time=1846422", 0, NULL, 0)) {
                printf("not ");
            }
            if (strcmp(mod->replacement, expectreplace)) {
                printf("not ");
            } else if (mod->t != 102 || mod->vendor != 9) {
                printf("not ");
            }
            printf("ok %d - rewrite config issue #62\n", numtests++);
        } else {
            printf("not ok %d - rewrite config issue #62\n", numtests++);
        }
    }

    /* test meta attribute config */
    {
        char **addmeta = malloc(2 * sizeof(char *));
        char **addmetav = malloc(2 * sizeof(char *));
        char **supmeta = malloc(2 * sizeof(char *));
        char **supmetav = malloc(2 * sizeof(char *));
        struct dynattr *add1 = NULL, *add2 = NULL, *sup1 = NULL, *sup2 = NULL;
        rewritename = "meta";

        addmeta[0] = stringcopy("31:source_ip", 0);
        addmeta[1] = NULL;
        addmetav[0] = stringcopy("12345:1:client_name", 0);
        addmetav[1] = NULL;
        supmeta[0] = stringcopy("32:client_name", 0);
        supmeta[1] = NULL;
        supmetav[0] = stringcopy("12345:2:source_port", 0);
        supmetav[1] = NULL;

        addrewrite(rewritename, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                   addmeta, addmetav, supmeta, supmetav);
        result = getrewrite(rewritename, NULL);

        if (result && result->addmetaattrs && list_count(result->addmetaattrs) == 2 &&
            result->supmetaattrs && list_count(result->supmetaattrs) == 2) {
            add1 = (struct dynattr *)list_first(result->addmetaattrs)->data;
            add2 = (struct dynattr *)list_next(list_first(result->addmetaattrs))->data;
            sup1 = (struct dynattr *)list_first(result->supmetaattrs)->data;
            sup2 = (struct dynattr *)list_next(list_first(result->supmetaattrs))->data;
        }
        if (!add1 || add1->t != 31 || add1->vendor != 0 || strcmp(add1->field, "source_ip") ||
            add2->t != 1 || add2->vendor != 12345 || strcmp(add2->field, "client_name") ||
            sup1->t != 32 || sup1->vendor != 0 || strcmp(sup1->field, "client_name") ||
            sup2->t != 2 || sup2->vendor != 12345 || strcmp(sup2->field, "source_port"))
            printf("not ");
        printf("ok %d - rewrite config meta attributes\n", numtests++);
    }

    return 0;
}
