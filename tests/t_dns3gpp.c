/* Copyright (C) 2026, CyB0rgg */
/* See LICENSE for licensing information. */

#include "../dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(int *testcount, const char *realm, const char *expected, const char *name) {
    char *result = dns3gpppublicname(realm);
    int ok = (!result && !expected) || (result && expected && strcmp(result, expected) == 0);

    if (!ok) {
        printf("# realm %s: expected %s, got %s\n", realm ? realm : "(null)",
               expected ? expected : "(null)", result ? result : "(null)");
        printf("not ");
    }
    printf("ok %d - %s\n", ++*testcount, name);
    free(result);
    return ok;
}

int main(int argc, char *argv[]) {
    int testcount = 0;

    /* the normative case, draft-tomas-openroaming section 6.2 */
    check(&testcount, "wlan.mnc410.mcc310.3gppnetwork.org", "wlan.mnc410.mcc310.pub.3gppnetwork.org", "bare 3GPP realm gets .pub inserted");
    /* already public: leave alone */
    check(&testcount, "wlan.mnc410.mcc310.pub.3gppnetwork.org", NULL, "realm already under pub. is left alone");
    /* case is preserved, matching is case-insensitive */
    check(&testcount, "WLAN.MNC410.MCC310.3GPPNETWORK.ORG", "WLAN.MNC410.MCC310.pub.3GPPNETWORK.ORG", "upper case realm, case preserved");
    /* IR.67 delegates the whole mnc.mcc.pub sub-domain, so any prefix or none */
    check(&testcount, "ims.mnc001.mcc001.3gppnetwork.org", "ims.mnc001.mcc001.pub.3gppnetwork.org", "other 3GPP prefix");
    check(&testcount, "mnc001.mcc001.3gppnetwork.org", "mnc001.mcc001.pub.3gppnetwork.org", "shortest form");
    /* not 3GPP at all */
    check(&testcount, "example.com", NULL, "ordinary realm untouched");
    check(&testcount, "eduroam.3gppnetwork.org", NULL, "3gppnetwork.org without mnc/mcc labels");
    check(&testcount, "wlan.mnc41.mcc310.3gppnetwork.org", NULL, "two-digit mnc is not a valid 3GPP realm");
    check(&testcount, "wlan.mnc0410.mcc310.3gppnetwork.org", NULL, "four-digit mnc is not a valid 3GPP realm");
    check(&testcount, "xmnc410.mcc310.3gppnetwork.org", NULL, "mnc label must start at a label boundary");
    check(&testcount, "wlan.mncabc.mcc310.3gppnetwork.org", NULL, "mnc must be digits");
    check(&testcount, "wlan.mnc410.mcc3x0.3gppnetwork.org", NULL, "mcc must be digits");
    check(&testcount, "wlan.mnc410.mcc310.3gppnetwork.org.", NULL, "trailing dot is not touched");
    check(&testcount, "3gppnetwork.org", NULL, "bare domain");
    check(&testcount, "", NULL, "empty realm");
    check(&testcount, NULL, NULL, "null realm");
    /* an unrelated domain with the suffix embedded in a label */
    check(&testcount, "mnc410.mcc310.3gppnetwork.org.example.com", NULL, "suffix not at the end");

    printf("1..%d\n", testcount);
    return 0;
}
