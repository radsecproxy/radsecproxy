/* Copyright (C) 2019, SWITCH */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rewrite.h"
#include "../radmsg.h"
#include "../debug.h"
#include "../util.h"

int
main (int argc, char *argv[])
{
    struct rewrite *result;
    char *rewritename = "rewrite";
    char **addattrs;
    int numtests = 2, i;
    struct tlv *tlv, *expected;
    uint8_t expectedvalue[] = {'1',0,0,'1','A','%','4','1'};

    printf("1..%d\n", numtests);
    numtests = 1;

    {
        addattrs = malloc(2*sizeof(char*));
        addattrs[0] = stringcopy("1:'1%00%001%41%2541", 0);
        addattrs[1] = NULL;

        expected = maketlv(1,8,expectedvalue);

        addrewrite(rewritename, 0, NULL, NULL, addattrs,
                        NULL, NULL, NULL, NULL, NULL);

        result = getrewrite(rewritename, NULL);

        if (result->addattrs->first) {
            tlv = (struct tlv *)result->addattrs->first->data;
            if (!eqtlv(tlv, expected)) {
                printf ("tlv value was: 0x");
                for (i = 0; i < tlv->l; i++) {
                    printf ("%x", *((tlv->v)+i));
                }
                printf ("\n");
                printf ("not ");
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
        char **modvattrs = malloc(2*sizeof(char*));
        rewritename= "issue62";

        modvattrs[0] = stringcopy("9:102:/^(h323-credit-time).*$/\\1=86400/",0);
        modvattrs[1] = NULL;

        addrewrite(rewritename, 0, NULL, NULL, NULL, NULL, NULL, modvattrs, NULL, NULL);
        result = getrewrite(rewritename, NULL);

        if (result && result->modvattrs && result->modvattrs->first) {
            struct modattr *mod = (struct modattr *)result->modvattrs->first->data;
            if (regexec(mod->regex,"h323-credit-time=1846422",0,NULL,0)) {
                printf("not ");
            }
            if (strcmp(mod->replacement, expectreplace)) {
                printf("not ");
            }
            else if (mod->t != 102 || mod->vendor != 9) {
                printf("not ");
            }
            printf("ok %d - rewrite config issue #62\n", numtests++);
        } else {
            printf("not ok %d - rewrite config issue #62\n", numtests++);
        }
    }

    return 0;
}
