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
    int numtests = 1, i;
    struct tlv *tlv, *expected;
    uint8_t expectedvalue[] = {'1',0,0,'1','A'};

    printf("1..%d\n", numtests);
    numtests = 1;

    addattrs = malloc(2);
    addattrs[0] = stringcopy("1:'1%00%001%41", 0);
    addattrs[1] = NULL;

    expected = maketlv(1,5,expectedvalue);

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
        printf("not ok %d - rewrite ocnfig\n", numtests++);
    }


    return 0;
}
