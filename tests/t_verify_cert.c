/* Copyright (C) 2020, SWITCH */
/* See LICENSE for licensing information. */

#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include "../radsecproxy.h"
#include "../debug.h"
#include "../hostport.h"

/* /CN=test */
char *certsimplepem = "-----BEGIN CERTIFICATE-----\n\
MIHAMIGMAgkAx2VNeC1d5FswCQYHKoZIzj0EATAPMQ0wCwYDVQQDDAR0ZXN0MB4X\n\
DTIwMDkyODE0MTEzMloXDTIwMTAwODE0MTEzMlowDzENMAsGA1UEAwwEdGVzdDAy\n\
MBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQMNcK0IZozUpupFkD/dWBC37qI\n\
QW4wCQYHKoZIzj0EAQMkADAhAg8Ajl0dHSkadggaqZiD72ACDjWHqYhaIAWTstBv\n\
g/Q5\n\
-----END CERTIFICATE-----";

/* /CN=other */
char *certsimpleotherpem = "-----BEGIN CERTIFICATE-----\n\
MIHDMIGOAgkAwf1w/+YshIwwCQYHKoZIzj0EATAQMQ4wDAYDVQQDDAVvdGhlcjAe\n\
Fw0yMDA5MjkwNTE1MjlaFw0yMDEwMDkwNTE1MjlaMBAxDjAMBgNVBAMMBW90aGVy\n\
MDIwEAYHKoZIzj0CAQYFK4EEAAYDHgAEnGezNfbihAw1wrQhmjNSm6kWQP91YELf\n\
uohBbjAJBgcqhkjOPQQBAyUAMCICDwDD9T+qjNHU461al3c11gIPAMZbk5wkhd6C\n\
ybOsj/PY\n\
-----END CERTIFICATE-----";

/* /CN=test, SAN DNS:test.local */
char *certsandnspem = "-----BEGIN CERTIFICATE-----\n\
MIHrMIG3oAMCAQICFGNCMLUfhveEcLQmEnX2DqjwFZpGMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNjA4NTRaFw0yMDEwMDkxNjA4NTRaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxkwFzAVBgNVHREEDjAMggp0ZXN0LmxvY2FsMAkG\n\
ByqGSM49BAEDJAAwIQIPAId8FJW00y8XSFmd2lBvAg5K6WAMIFgjhtwcRFcfQg==\n\
-----END CERTIFICATE-----";

/* /CN=other, SAN DNS:other.local */
char *certsandnsotherpem = "-----BEGIN CERTIFICATE-----\n\
MIHuMIG6oAMCAQICFAiFPNqpXcSIwxS0bfJZs8KDDafVMAkGByqGSM49BAEwEDEO\n\
MAwGA1UEAwwFb3RoZXIwHhcNMjAwOTI5MTYxMTM2WhcNMjAxMDA5MTYxMTM2WjAQ\n\
MQ4wDAYDVQQDDAVvdGhlcjAyMBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQM\n\
NcK0IZozUpupFkD/dWBC37qIQW6jGjAYMBYGA1UdEQQPMA2CC290aGVyLmxvY2Fs\n\
MAkGByqGSM49BAEDJAAwIQIOTrQCgOkGcknZEchJFDgCDwCY84F0R2BnNEba95o9\n\
NA==\n\
-----END CERTIFICATE-----";

/* /CN=test, SAN IP Address:192.0.2.1 */
char *certsanippem = "-----BEGIN CERTIFICATE-----\n\
MIHlMIGxoAMCAQICFEukd75rE75+qB95Bo7fcb9wXlA9MAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkwNTQ5MjZaFw0yMDEwMDkwNTQ5MjZaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxMwETAPBgNVHREECDAGhwTAAAIBMAkGByqGSM49\n\
BAEDJAAwIQIPALa7jf16ypPNHJSLiotwAg4DnSeToNmbqlRsvM80Aw==\n\
-----END CERTIFICATE-----";

/* /CN=other, SAN IP Address:192.0.2.2 */
char *certsanipotherpem = "-----BEGIN CERTIFICATE-----\n\
MIHmMIGzoAMCAQICFCYvcOo1Lqc+9JbYqfby1S9rJWufMAkGByqGSM49BAEwEDEO\n\
MAwGA1UEAwwFb3RoZXIwHhcNMjAwOTI5MTU0OTM2WhcNMjAxMDA5MTU0OTM2WjAQ\n\
MQ4wDAYDVQQDDAVvdGhlcjAyMBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQM\n\
NcK0IZozUpupFkD/dWBC37qIQW6jEzARMA8GA1UdEQQIMAaHBMAAAgIwCQYHKoZI\n\
zj0EAQMjADAgAg5trehJeRpM04SJJZ6XnAIOFfzRRnQtm5rnsP+QBe8=\n\
-----END CERTIFICATE-----";

/* /CN=test, SAN IP Address:2001:DB8:0:0:0:0:0:1 */
char *certsanipv6pem = "-----BEGIN CERTIFICATE-----\n\
MIHxMIG9oAMCAQICFGhkABYXfolor1EF6Li3hDQeEVU+MAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNTU1NTZaFw0yMDEwMDkxNTU1NTZaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuox8wHTAbBgNVHREEFDAShxAgAQ24AAAAAAAAAAAA\n\
AAABMAkGByqGSM49BAEDJAAwIQIPAKsn++FWaDIcpnNBOFTuAg5C7gs7DxaNWgEu\n\
OrBTXA==\n\
-----END CERTIFICATE-----";

/* /CN=test, SAN DNS:192.0.2.1 */
char *certsanipindnspem = "-----BEGIN CERTIFICATE-----\n\
MIHqMIG2oAMCAQICFFUjZGG96kpFI2fu90+jAhWsTr8YMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNTU4NDBaFw0yMDEwMDkxNTU4NDBaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxgwFjAUBgNVHREEDTALggkxOTIuMC4yLjEwCQYH\n\
KoZIzj0EAQMkADAhAg5BngyplTbRlQ8o/oWWwQIPAL9SfgIaXi/gD6YlQCOU\n\
-----END CERTIFICATE-----";

/* /CN=test, SAN DNS:2001:DB8::1 */
char *certsanipv6indnspem = "-----BEGIN CERTIFICATE-----\n\
MIHsMIG4oAMCAQICFFgnXltbOEGcWsS0vCv6Lsj4FhO3MAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNjAyMDRaFw0yMDEwMDkxNjAyMDRaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxowGDAWBgNVHREEDzANggsyMDAxOmRiODo6MTAJ\n\
BgcqhkjOPQQBAyQAMCECDlWFhJxpHRgt93ZzN9k7Ag8Ag0YN+dL3MEIo2sqgRWg=\n\
-----END CERTIFICATE-----";

/* /CN=test, DNS:somethinglese, DNS:test.local, IP Address:192.0.2.1, IP Address:2001:DB8:0:0:0:0:0:1 */
char *certcomplexpem = "-----BEGIN CERTIFICATE-----\n\
MIIBEjCB3qADAgECAhRgxyW7klgZvTf9isALCvwlVwvRtDAJBgcqhkjOPQQBMA8x\n\
DTALBgNVBAMMBHRlc3QwHhcNMjAwOTMwMDU1MjIyWhcNMjAxMDEwMDU1MjIyWjAP\n\
MQ0wCwYDVQQDDAR0ZXN0MDIwEAYHKoZIzj0CAQYFK4EEAAYDHgAEnGezNfbihAw1\n\
wrQhmjNSm6kWQP91YELfuohBbqNAMD4wPAYDVR0RBDUwM4INc29tZXRoaW5nbGVz\n\
ZYIKdGVzdC5sb2NhbIcEwAACAYcQIAENuAAAAAAAAAAAAAAAATAJBgcqhkjOPQQB\n\
AyQAMCECDlTfJfMJElZZgvUdkatdAg8ApiXkPXLXXrV6OMRG9us=\n\
-----END CERTIFICATE-----";

/* /CN=test, DNS:somethinglese, DNS:other.local, IP Address:192.0.2.2, IP Address:2001:DB8:0:0:0:0:0:2 */
char *certcomplexotherpem = "-----BEGIN CERTIFICATE-----\n\
MIIBFTCB4aADAgECAhR0GSgeV7pqQnbHRgv5y5plz/6+NjAJBgcqhkjOPQQBMBAx\n\
DjAMBgNVBAMMBW90aGVyMB4XDTIwMDkzMDA1NTI1NVoXDTIwMTAxMDA1NTI1NVow\n\
EDEOMAwGA1UEAwwFb3RoZXIwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKE\n\
DDXCtCGaM1KbqRZA/3VgQt+6iEFuo0EwPzA9BgNVHREENjA0gg1zb21ldGhpbmds\n\
ZXNlggtvdGhlci5sb2NhbIcEwAACAocQIAENuAAAAAAAAAAAAAAAAjAJBgcqhkjO\n\
PQQBAyQAMCECDwCEaHL6oHT4zwH6jD91YwIOYO3L8cHIzmnGCOJYIQ4=\n\
-----END CERTIFICATE-----";

X509 *getcert(char *pem) {
    X509* certX509;
    BIO* certBio;

    certBio = BIO_new(BIO_s_mem());
    BIO_write(certBio, pem , strlen(pem));
    certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);

    BIO_free(certBio);

    return certX509;
}

int numtests = 0;
void ok(int expect, int result, char *descr) {
    if (result == expect) {
        printf("ok %d - %s\n", ++numtests, descr);
    } else {
        printf("not ok %d - %s\n", ++numtests, descr);
    }
}

int
main (int argc, char *argv[])
{
    struct clsrvconf conf;
    X509 *certsimple, *certsimpleother, *certsandns, *certsandnsother, *certsanip, *certsanipother, *certsanipindns,
        *certsanipv6, *certsanipv6indns, *certcomplex, *certcomplexother;

    certsimple = getcert(certsimplepem);
    certsimpleother = getcert(certsimpleotherpem);
    certsandns = getcert(certsandnspem);
    certsandnsother = getcert(certsandnsotherpem);
    certsanip = getcert(certsanippem);
    certsanipother = getcert(certsanipotherpem);
    certsanipindns = getcert(certsanipindnspem);
    certsanipv6 = getcert(certsanipv6pem);
    certsanipv6indns = getcert(certsanipv6indnspem);
    certcomplex = getcert(certcomplexpem);
    certcomplexother = getcert(certcomplexotherpem);

    memset(&conf, 0, sizeof(conf));
    conf.hostports = list_create();

    debug_init("t_verify_cert");
    debug_set_level(5);

    /* test check disabled*/
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 0;
        conf.matchcertattr = NULL;
        hp.host = "test";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsimple, &conf), "check disabled");

        while(list_shift(conf.hostports));
    }

    /* test no check if prefixlen != 255 (CIDR) */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattr = NULL;
        hp.host = "0.0.0.0/0";
        hp.prefixlen = 0;
        list_push(conf.hostports, &hp);

        ok(1,verifyconfcert(certsimple, &conf),"cidr prefix");

        while(list_shift(conf.hostports));
    }

    /* test simple match for CN=test */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattr = NULL;
        hp.host = "test";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1,verifyconfcert(certsimple, &conf), "simple cert cn");
        ok(0,verifyconfcert(certsimpleother, &conf), "negative simple cert cn");

        /* as per RFC 6125 6.4.4: CN MUST NOT be matched if SAN is present */
        ok(0,verifyconfcert(certsandns, &conf), "simple cert cn vs san dns, RFC6125");

        while(list_shift(conf.hostports));
    }

    /* test literal ip match to SAN IP */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattr = NULL;
        hp.host = "192.0.2.1";
        getaddrinfo(hp.host, NULL, NULL, &hp.addrinfo);
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1,verifyconfcert(certsanip, &conf),"san ip");
        ok(0,verifyconfcert(certsanipother, &conf),"wrong san ip");
        ok(0,verifyconfcert(certsimple, &conf), "negative san ip");
        ok(1,verifyconfcert(certsanipindns, &conf),"san ip in dns");
        ok(1,verifyconfcert(certcomplex,&conf),"san ip in complex cert");

        freeaddrinfo(hp.addrinfo);
        while(list_shift(conf.hostports));
    }

    /* test literal ipv6 match to SAN IP */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattr = NULL;
        hp.host = "2001:db8::1";
        getaddrinfo(hp.host, NULL, NULL, &hp.addrinfo);
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1,verifyconfcert(certsanipv6, &conf),"san ipv6");
        ok(0,verifyconfcert(certsanipother, &conf),"wrong san ipv6");
        ok(0,verifyconfcert(certsimple, &conf),"negative san ipv6");
        ok(1,verifyconfcert(certsanipv6indns, &conf),"san ipv6 in dns");
        ok(1,verifyconfcert(certcomplex,&conf),"san ipv6 in complex cert");

        freeaddrinfo(hp.addrinfo);
        while(list_shift(conf.hostports));
    }

    /* test simple match for SAN DNS:test.local */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattr = NULL;
        hp.host = "test.local";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1,verifyconfcert(certsandns, &conf),"san dns");
        ok(0,verifyconfcert(certsandnsother, &conf),"negative san dns");
        ok(1,verifyconfcert(certcomplex,&conf),"san dns in complex cert");

        while(list_shift(conf.hostports));
    }

    /* test multiple hostports san dns(match in second) */
    {
        struct hostportres hp1, hp2;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattr = NULL;
        hp1.host = "test.none";
        hp1.prefixlen = 255;
        list_push(conf.hostports, &hp1);
        hp2.host = "test";
        hp2.prefixlen = 255;
        list_push(conf.hostports, &hp2);

        ok(1,verifyconfcert(certsimple, &conf),"multi hostport cn");
        ok(0,verifyconfcert(certsimpleother, &conf),"negative multi hostport cn");

        while(list_shift(conf.hostports));
    }

    /* test multiple hostports san dns(match in second) */
    {
        struct hostportres hp1, hp2;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattr = NULL;
        hp1.host = "test.none";
        hp1.prefixlen = 255;
        list_push(conf.hostports, &hp1);
        hp2.host = "test.local";
        hp2.prefixlen = 255;
        list_push(conf.hostports, &hp2);

        ok(1,verifyconfcert(certsandns, &conf),"multi hostport san dns # TODO fix in refactoring");
        ok(0,verifyconfcert(certsandnsother, &conf),"negative multi hostport san dns");
        ok(1,verifyconfcert(certcomplex,&conf),"multi hostport san dns in complex cert # TODO fix in refactoring");

        while(list_shift(conf.hostports));
    }

    //TODO explicit CN/SAN checks
    //TODO explicit & implicit combined

    printf("1..%d\n", numtests);
    X509_free(certsimple);
    X509_free(certsimpleother);
    X509_free(certsandns);
    X509_free(certsandnsother);
    X509_free(certsanip);
    X509_free(certsanipother);
    X509_free(certsanipindns);
    X509_free(certsanipv6);
    X509_free(certsanipv6indns);
    X509_free(certcomplex);
    X509_free(certcomplexother);

    return 0;
}
