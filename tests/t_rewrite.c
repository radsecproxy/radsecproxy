/* Copyright (C) 2019, SWITCH */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rewrite.h"
#include "../radmsg.h"

/*origattrs and expectedattrs as struct tlv*/
/*return 0 if expected; 1 otherwise or error*/
static int
_check_rewrite(struct list *origattrs, struct rewrite *rewrite, struct list *expectedattrs) {
    struct radmsg msg;
    struct list_node *n,*m;

    msg.attrs = origattrs;

    if(!dorewrite(&msg, rewrite))
        return 1;

    if(list_count(expectedattrs) != list_count(origattrs)) {
        printf("bad attribute list length!");
        return 1;
    }
    m=list_first(origattrs);
    for(n=list_first(expectedattrs); n; n=list_next(n)) {
        if (((struct tlv *)n->data)->t != ((struct tlv *)m->data)->t ||
            ((struct tlv *)n->data)->l != ((struct tlv *)m->data)->l ||
            memcmp(((struct tlv *)n->data)->v, ((struct tlv *)m->data)->v, ((struct tlv *)n->data)->l) ) {

            printf("attribute list not as expected");
            return 1;
        }
        m=list_next(m);
    }
    return 0;
}

int
main (int argc, char *argv[])
{
    struct list *origattrs, *expectedattrs;
    struct rewrite rewrite;

    origattrs=list_create();
    expectedattrs=list_create();

    rewrite.removeattrs = NULL;
    rewrite.removevendorattrs = NULL;
    rewrite.addattrs = list_create();
    rewrite.modattrs = list_create();
    rewrite.supattrs = list_create();

    /* test 1: empty noop */
    if (_check_rewrite(origattrs, &rewrite, expectedattrs))
        return 1;

  return 0;
}
