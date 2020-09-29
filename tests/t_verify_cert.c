/* Copyright (C) 2020, SWITCH */
/* See LICENSE for licensing information. */

#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>
#include "../radsecproxy.h"
#include "../debug.h"
#include "../hostport.h"

/* /CN=test */
char *simplecert = "-----BEGIN CERTIFICATE-----\n\
MIHAMIGMAgkAx2VNeC1d5FswCQYHKoZIzj0EATAPMQ0wCwYDVQQDDAR0ZXN0MB4X\n\
DTIwMDkyODE0MTEzMloXDTIwMTAwODE0MTEzMlowDzENMAsGA1UEAwwEdGVzdDAy\n\
MBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQMNcK0IZozUpupFkD/dWBC37qI\n\
QW4wCQYHKoZIzj0EAQMkADAhAg8Ajl0dHSkadggaqZiD72ACDjWHqYhaIAWTstBv\n\
g/Q5\n\
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

int
main (int argc, char *argv[])
{
    int numtests = 1;

    struct clsrvconf conf;
    X509 *cert;

    debug_init("t_verify_cert");
    debug_set_level(5);

    printf("1..%d\n", numtests);

    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        conf.matchcertattrs = NULL;
        conf.hostports = list_create();
        hp.host = "test";
        hp.prefixlen = 0;
        list_push(conf.hostports, &hp);

        cert = getcert(simplecert);

        if (verifyconfcert(cert, &conf)) {
            printf("ok %d - simple cert cn\n", numtests++);
        } else {
            printf("not ok %d - simple cert cn\n", numtests++);
        }
        X509_free(cert);
    }

    return 0;
}
