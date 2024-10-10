/* Copyright (C) 2020, SWITCH */
/* See LICENSE for licensing information. */

#include "../debug.h"
#include "../hostport.h"
#include "../radsecproxy.h"
#include "../util.h"
#include <netdb.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

X509 *getcert(char *pem) {
    X509 *certX509;
    BIO *certBio;

    certBio = BIO_new(BIO_s_mem());
    BIO_write(certBio, pem, strlen(pem));
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

int main(int argc, char *argv[]) {
    struct clsrvconf conf;

    /* /CN=test */
    X509 *certsimple = getcert("-----BEGIN CERTIFICATE-----\n\
MIHAMIGMAgkAx2VNeC1d5FswCQYHKoZIzj0EATAPMQ0wCwYDVQQDDAR0ZXN0MB4X\n\
DTIwMDkyODE0MTEzMloXDTIwMTAwODE0MTEzMlowDzENMAsGA1UEAwwEdGVzdDAy\n\
MBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQMNcK0IZozUpupFkD/dWBC37qI\n\
QW4wCQYHKoZIzj0EAQMkADAhAg8Ajl0dHSkadggaqZiD72ACDjWHqYhaIAWTstBv\n\
g/Q5\n\
-----END CERTIFICATE-----");

    /* /CN=other */
    X509 *certsimpleother = getcert("-----BEGIN CERTIFICATE-----\n\
MIHDMIGOAgkAwf1w/+YshIwwCQYHKoZIzj0EATAQMQ4wDAYDVQQDDAVvdGhlcjAe\n\
Fw0yMDA5MjkwNTE1MjlaFw0yMDEwMDkwNTE1MjlaMBAxDjAMBgNVBAMMBW90aGVy\n\
MDIwEAYHKoZIzj0CAQYFK4EEAAYDHgAEnGezNfbihAw1wrQhmjNSm6kWQP91YELf\n\
uohBbjAJBgcqhkjOPQQBAyUAMCICDwDD9T+qjNHU461al3c11gIPAMZbk5wkhd6C\n\
ybOsj/PY\n\
-----END CERTIFICATE-----");

    /* /CN=test, SAN DNS:test.local */
    X509 *certsandns = getcert("-----BEGIN CERTIFICATE-----\n\
MIHrMIG3oAMCAQICFGNCMLUfhveEcLQmEnX2DqjwFZpGMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNjA4NTRaFw0yMDEwMDkxNjA4NTRaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxkwFzAVBgNVHREEDjAMggp0ZXN0LmxvY2FsMAkG\n\
ByqGSM49BAEDJAAwIQIPAId8FJW00y8XSFmd2lBvAg5K6WAMIFgjhtwcRFcfQg==\n\
-----END CERTIFICATE-----");

    /* /CN=other, SAN DNS:other.local */
    X509 *certsandnsother = getcert("-----BEGIN CERTIFICATE-----\n\
MIHuMIG6oAMCAQICFAiFPNqpXcSIwxS0bfJZs8KDDafVMAkGByqGSM49BAEwEDEO\n\
MAwGA1UEAwwFb3RoZXIwHhcNMjAwOTI5MTYxMTM2WhcNMjAxMDA5MTYxMTM2WjAQ\n\
MQ4wDAYDVQQDDAVvdGhlcjAyMBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQM\n\
NcK0IZozUpupFkD/dWBC37qIQW6jGjAYMBYGA1UdEQQPMA2CC290aGVyLmxvY2Fs\n\
MAkGByqGSM49BAEDJAAwIQIOTrQCgOkGcknZEchJFDgCDwCY84F0R2BnNEba95o9\n\
NA==\n\
-----END CERTIFICATE-----");

    /* /CN=test, SAN IP Address:192.0.2.1 */
    X509 *certsanip = getcert("-----BEGIN CERTIFICATE-----\n\
MIHlMIGxoAMCAQICFEukd75rE75+qB95Bo7fcb9wXlA9MAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkwNTQ5MjZaFw0yMDEwMDkwNTQ5MjZaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxMwETAPBgNVHREECDAGhwTAAAIBMAkGByqGSM49\n\
BAEDJAAwIQIPALa7jf16ypPNHJSLiotwAg4DnSeToNmbqlRsvM80Aw==\n\
-----END CERTIFICATE-----");

    /* /CN=other, SAN IP Address:192.0.2.2 */
    X509 *certsanipother = getcert("-----BEGIN CERTIFICATE-----\n\
MIHmMIGzoAMCAQICFCYvcOo1Lqc+9JbYqfby1S9rJWufMAkGByqGSM49BAEwEDEO\n\
MAwGA1UEAwwFb3RoZXIwHhcNMjAwOTI5MTU0OTM2WhcNMjAxMDA5MTU0OTM2WjAQ\n\
MQ4wDAYDVQQDDAVvdGhlcjAyMBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQM\n\
NcK0IZozUpupFkD/dWBC37qIQW6jEzARMA8GA1UdEQQIMAaHBMAAAgIwCQYHKoZI\n\
zj0EAQMjADAgAg5trehJeRpM04SJJZ6XnAIOFfzRRnQtm5rnsP+QBe8=\n\
-----END CERTIFICATE-----");

    /* /CN=test, SAN IP Address:2001:DB8:0:0:0:0:0:1 */
    X509 *certsanipv6 = getcert("-----BEGIN CERTIFICATE-----\n\
MIHxMIG9oAMCAQICFGhkABYXfolor1EF6Li3hDQeEVU+MAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNTU1NTZaFw0yMDEwMDkxNTU1NTZaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuox8wHTAbBgNVHREEFDAShxAgAQ24AAAAAAAAAAAA\n\
AAABMAkGByqGSM49BAEDJAAwIQIPAKsn++FWaDIcpnNBOFTuAg5C7gs7DxaNWgEu\n\
OrBTXA==\n\
-----END CERTIFICATE-----");

    /* /CN=test, SAN DNS:192.0.2.1 */
    X509 *certsanipindns = getcert("-----BEGIN CERTIFICATE-----\n\
MIHqMIG2oAMCAQICFFUjZGG96kpFI2fu90+jAhWsTr8YMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNTU4NDBaFw0yMDEwMDkxNTU4NDBaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxgwFjAUBgNVHREEDTALggkxOTIuMC4yLjEwCQYH\n\
KoZIzj0EAQMkADAhAg5BngyplTbRlQ8o/oWWwQIPAL9SfgIaXi/gD6YlQCOU\n\
-----END CERTIFICATE-----");

    /* /CN=test, SAN DNS:2001:DB8::1 */
    X509 *certsanipv6indns = getcert("-----BEGIN CERTIFICATE-----\n\
MIHsMIG4oAMCAQICFFgnXltbOEGcWsS0vCv6Lsj4FhO3MAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDA5MjkxNjAyMDRaFw0yMDEwMDkxNjAyMDRaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxowGDAWBgNVHREEDzANggsyMDAxOmRiODo6MTAJ\n\
BgcqhkjOPQQBAyQAMCECDlWFhJxpHRgt93ZzN9k7Ag8Ag0YN+dL3MEIo2sqgRWg=\n\
-----END CERTIFICATE-----");

    /* /CN=test, DNS:somethinglese, DNS:test.local, IP Address:192.0.2.1, IP Address:2001:DB8:0:0:0:0:0:1 */
    X509 *certcomplex = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBEjCB3qADAgECAhRgxyW7klgZvTf9isALCvwlVwvRtDAJBgcqhkjOPQQBMA8x\n\
DTALBgNVBAMMBHRlc3QwHhcNMjAwOTMwMDU1MjIyWhcNMjAxMDEwMDU1MjIyWjAP\n\
MQ0wCwYDVQQDDAR0ZXN0MDIwEAYHKoZIzj0CAQYFK4EEAAYDHgAEnGezNfbihAw1\n\
wrQhmjNSm6kWQP91YELfuohBbqNAMD4wPAYDVR0RBDUwM4INc29tZXRoaW5nbGVz\n\
ZYIKdGVzdC5sb2NhbIcEwAACAYcQIAENuAAAAAAAAAAAAAAAATAJBgcqhkjOPQQB\n\
AyQAMCECDlTfJfMJElZZgvUdkatdAg8ApiXkPXLXXrV6OMRG9us=\n\
-----END CERTIFICATE-----");

    /* /CN=test, DNS:somethinglese, DNS:other.local, IP Address:192.0.2.2, IP Address:2001:DB8:0:0:0:0:0:2 */
    X509 *certcomplexother = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBFTCB4aADAgECAhR0GSgeV7pqQnbHRgv5y5plz/6+NjAJBgcqhkjOPQQBMBAx\n\
DjAMBgNVBAMMBW90aGVyMB4XDTIwMDkzMDA1NTI1NVoXDTIwMTAxMDA1NTI1NVow\n\
EDEOMAwGA1UEAwwFb3RoZXIwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKE\n\
DDXCtCGaM1KbqRZA/3VgQt+6iEFuo0EwPzA9BgNVHREENjA0gg1zb21ldGhpbmds\n\
ZXNlggtvdGhlci5sb2NhbIcEwAACAocQIAENuAAAAAAAAAAAAAAAAjAJBgcqhkjO\n\
PQQBAyQAMCECDwCEaHL6oHT4zwH6jD91YwIOYO3L8cHIzmnGCOJYIQ4=\n\
-----END CERTIFICATE-----");

    /* /CN=test, URI:https://test.local/profile#me */
    X509 *certsanuri = getcert("-----BEGIN CERTIFICATE-----\n\
MIH9MIHKoAMCAQICFHsSOjcYexRKQpNlH1oHV1cxvdgHMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDEwMDYwODU5MzRaFw0yMDEwMTYwODU5MzRaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoywwKjAoBgNVHREEITAfhh1odHRwczovL3Rlc3Qu\n\
bG9jYWwvcHJvZmlsZSNtZTAJBgcqhkjOPQQBAyMAMCACDniwUmV285CoguiJ6WmW\n\
Ag5ZWNTJtmNNdKxh0Mahsw==\n\
-----END CERTIFICATE-----");

    /* /CN=other, URI:https://other.local/profile#me */
    X509 *certsanuriother = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBATCBzaADAgECAhQLG7rYpl+8YbPNEtUgw6HRZYIc1DAJBgcqhkjOPQQBMBAx\n\
DjAMBgNVBAMMBW90aGVyMB4XDTIwMTAwNjA5MDU0OVoXDTIwMTAxNjA5MDU0OVow\n\
EDEOMAwGA1UEAwwFb3RoZXIwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKE\n\
DDXCtCGaM1KbqRZA/3VgQt+6iEFuoy0wKzApBgNVHREEIjAghh5odHRwczovL290\n\
aGVyLmxvY2FsL3Byb2ZpbGUjbWUwCQYHKoZIzj0EAQMkADAhAg8AoOJVnRcp3gyY\n\
Qe0Vy/UCDijCHK6Y5GkzWD7H008l\n\
-----END CERTIFICATE-----");

    /* /CN=test, Registered ID:1.2.3.4 */
    X509 *certsanrid = getcert("-----BEGIN CERTIFICATE-----\n\
MIHjMIGwoAMCAQICFBKq59XodNaMiLZDZbE7BMFn+GnAMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDEwMDYxNTA1NTBaFw0yMDEwMTYxNTA1NTBaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoxIwEDAOBgNVHREEBzAFiAMqAwQwCQYHKoZIzj0E\n\
AQMjADAgAg4QFOirxwoC5OYpFArE8gIORG+zCoikzhvY95kBGvg=\n\
-----END CERTIFICATE-----");

    /* /CN=other, Registered ID:1.2.3.9 */
    X509 *certsanridother = getcert("-----BEGIN CERTIFICATE-----\n\
MIHmMIGyoAMCAQICFEvhI4VZvPr7cITrckvz6J576uy3MAkGByqGSM49BAEwEDEO\n\
MAwGA1UEAwwFb3RoZXIwHhcNMjAxMDA2MTUwNzQzWhcNMjAxMDE2MTUwNzQzWjAQ\n\
MQ4wDAYDVQQDDAVvdGhlcjAyMBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQM\n\
NcK0IZozUpupFkD/dWBC37qIQW6jEjAQMA4GA1UdEQQHMAWIAyoDCTAJBgcqhkjO\n\
PQQBAyQAMCECDwCJMMBtTsOZNwvy43TlLgIOKtssl/hBDN/JcPbBQgI=\n\
-----END CERTIFICATE-----");

    /* /CN=test, otherNAME 1.3.6.1.5.5.7.8.8;UTF8:test.local (NAIRealm)*/
    X509 *certsanothername = getcert("-----BEGIN CERTIFICATE-----\n\
MIH4MIHFoAMCAQICFHfn1oV2cr4BkkWImdYCJXkSmiKrMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDEwMDYxNTE4NTNaFw0yMDEwMTYxNTE4NTNaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoycwJTAjBgNVHREEHDAaoBgGCCsGAQUFBwgIoAwM\n\
CnRlc3QubG9jYWwwCQYHKoZIzj0EAQMjADAgAg5picQbJfIM1Ljn7H/26QIOCLcA\n\
UXfI8XA07aHTgzE=\n\
-----END CERTIFICATE-----");

    /* /CN=other, otherNAME 1.3.6.1.5.5.7.8.8;UTF8:other.local (NAIRealm)*/
    X509 *certsanothernameother = getcert("-----BEGIN CERTIFICATE-----\n\
MIH6MIHGoAMCAQICFEa/hIvgCkqCF6ulCq3Jy3iw6XkwMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDEwMDYxNTIwMDhaFw0yMDEwMTYxNTIwMDhaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuoygwJjAkBgNVHREEHTAboBkGCCsGAQUFBwgIoA0M\n\
C290aGVyLmxvY2FsMAkGByqGSM49BAEDJAAwIQIOSOJ5OK2xzjrCweD/ImECDwDL\n\
COiok62ckBQsaUG8AA==\n\
-----END CERTIFICATE-----");

    /* /CN=test, DNS:test.local, Registered ID:1.2.3.4 */
    X509 *certmulti = getcert("-----BEGIN CERTIFICATE-----\n\
MIHxMIG8oAMCAQICFFrDaNQffsxLTERNbN7sXupYziWAMAkGByqGSM49BAEwDzEN\n\
MAsGA1UEAwwEdGVzdDAeFw0yMDEyMTgwOTQwMDFaFw0yMTAxMTcwOTQwMDFaMA8x\n\
DTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAScZ7M19uKEDDXC\n\
tCGaM1KbqRZA/3VgQt+6iEFuox4wHDAaBgNVHREEEzARggp0ZXN0LmxvY2FsiAMq\n\
AwQwCQYHKoZIzj0EAQMlADAiAg8AnsiRL2CH3u0bAX/FOt4CDwC9wGzr0l/PCnxK\n\
mKlpkQ==\n\
-----END CERTIFICATE-----");

    /* /CN=other, DNS:other.local, Registered ID:1.2.3.4 */
    X509 *certmultiother = getcert("-----BEGIN CERTIFICATE-----\n\
MIHyMIG/oAMCAQICFAke6IO1yAeuwOewT/QfAF9afFo7MAkGByqGSM49BAEwEDEO\n\
MAwGA1UEAwwFb3RoZXIwHhcNMjAxMjE4MDk0NTI1WhcNMjEwMTE3MDk0NTI1WjAQ\n\
MQ4wDAYDVQQDDAVvdGhlcjAyMBAGByqGSM49AgEGBSuBBAAGAx4ABJxnszX24oQM\n\
NcK0IZozUpupFkD/dWBC37qIQW6jHzAdMBsGA1UdEQQUMBKCC290aGVyLmxvY2Fs\n\
iAMqAwQwCQYHKoZIzj0EAQMjADAgAg521Y8BtyeKAMIY8lcLbwIORNNmcwVIJjGj\n\
vY/uPjA=\n\
-----END CERTIFICATE-----");

    /* /CN=test, DNS:*.test.local */
    X509 *certwildcard = getcert("-----BEGIN CERTIFICATE-----\n\
MIHkMIGvoAMCAQICCQCaS1+CEbAYJTAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDAR0\n\
ZXN0MB4XDTI0MDcxODA1MTU1M1oXDTI0MDgxNzA1MTU1M1owDzENMAsGA1UEAwwE\n\
dGVzdDAyMBAGByqGSM49AgEGBSuBBAAGAx4ABIK3s/AYIRC8j4vifUmVq+tz4K9v\n\
aIlHhc0QDZijGzAZMBcGA1UdEQQQMA6CDCoudGVzdC5sb2NhbDAKBggqhkjOPQQD\n\
AgMkADAhAg5G6uurUq7PVBD1GCfhVQIPANsQ3GyMIzfBGItySpEg\n\
-----END CERTIFICATE-----");

    /* /CN=test, DNS:*.*.test.local */
    X509 *certmultiwildcard = getcert("-----BEGIN CERTIFICATE-----\n\
MIHmMIGxoAMCAQICCQDwsiWIMHqzjjAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDAR0\n\
ZXN0MB4XDTI0MDcxODA1MTk1NloXDTI0MDgxNzA1MTk1NlowDzENMAsGA1UEAwwE\n\
dGVzdDAyMBAGByqGSM49AgEGBSuBBAAGAx4ABMaVo/xgQMK1XjQYlbazR/T2Xn0x\n\
163TlAEx5uOjHTAbMBkGA1UdEQQSMBCCDiouKi50ZXN0LmxvY2FsMAoGCCqGSM49\n\
BAMCAyQAMCECDwCYvguGalsnXCH0aOg11QIOIgHy1tsEk0KVTlOb4iU=\n\
-----END CERTIFICATE-----");

    /* /CN=test DNS:s*.test.local */
    X509 *certpartialwildcard = getcert("-----BEGIN CERTIFICATE-----\n\
MIHlMIGwoAMCAQICCQDsCbGkGdFS6DAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDAR0\n\
ZXN0MB4XDTI0MDcxODA1MjAzMloXDTI0MDgxNzA1MjAzMlowDzENMAsGA1UEAwwE\n\
dGVzdDAyMBAGByqGSM49AgEGBSuBBAAGAx4ABMrLs+w6vANs6EF3gdPaOutlYUJv\n\
SqeLf3m3iQCjHDAaMBgGA1UdEQQRMA+CDXMqLnRlc3QubG9jYWwwCgYIKoZIzj0E\n\
AwIDJAAwIQIPAKROuZI5oICWGV3wppUpAg4ucMPE3MjTatEQziO4Eg==\n\
-----END CERTIFICATE-----");

    /* /CN=test otherName 1.3.6.1.5.5.7.8.8;UTF8 *.local (NAIRealm)*/
    X509 *certnairealmwildcard = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBSjCCARSgAwIBAgIUGhwpQYy6p7F0bMMWIMHA+bRPtWkwCgYIKoZIzj0EAwIw\n\
DzENMAsGA1UEAwwEdGVzdDAeFw0yNDEwMDgxNzIzMzVaFw0yNDExMDcxNzIzMzVa\n\
MA8xDTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAQEGb/VgKm8\n\
n8TlwdOpcMdC6ilmxfu6tL2gBIwSo3UwczAdBgNVHQ4EFgQUuR6UE4EX4AON1i+6\n\
JPkIjjrIWuQwHwYDVR0jBBgwFoAUuR6UE4EX4AON1i+6JPkIjjrIWuQwDwYDVR0T\n\
AQH/BAUwAwEB/zAgBgNVHREEGTAXoBUGCCsGAQUFBwgIoAkMByoubG9jYWwwCgYI\n\
KoZIzj0EAwIDJAAwIQIPAJIGyq3vDVYpePXpgTZnAg5nsXFLasjCxCq+fkk5Jg==\n\
-----END CERTIFICATE-----");

    /* /CN=test otherName 1.3.6.1.5.5.7.8.8;UTF8 *.*.local (NAIRealm)*/
    X509 *certnairealmillegalwildcard = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBSzCCARagAwIBAgIUMYR54lRLzLghG8JKM5xz/Se70RMwCgYIKoZIzj0EAwIw\n\
DzENMAsGA1UEAwwEdGVzdDAeFw0yNDEwMDgxNzI5MjFaFw0yNDExMDcxNzI5MjFa\n\
MA8xDTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAARlsyBx/ihP\n\
1iHejnPQjAW6acblGcGGOEIOF+M1o3cwdTAdBgNVHQ4EFgQUCYzkY9FjITEcSMf7\n\
q7qZVcLnnjwwHwYDVR0jBBgwFoAUCYzkY9FjITEcSMf7q7qZVcLnnjwwDwYDVR0T\n\
AQH/BAUwAwEB/zAiBgNVHREEGzAZoBcGCCsGAQUFBwgIoAsMCSouKi5sb2NhbDAK\n\
BggqhkjOPQQDAgMjADAgAg4fYUMjVWHg+IDIxnYdQQIOQ8Tr0+DwhT8c/+tTHvo=\n\
-----END CERTIFICATE-----");

    /* /CN=test otherName 1.3.6.1.5.5.7.8.8;UTF8 *.a (NAIRealm)*/
    X509 *certnairealmshort = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBRjCCARCgAwIBAgIUTmQwOmLHY6MYjQTZMaKKSK9NLd0wCgYIKoZIzj0EAwIw\n\
DzENMAsGA1UEAwwEdGVzdDAeFw0yNDEwMDgxNzM0MTFaFw0yNDExMDcxNzM0MTFa\n\
MA8xDTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAS4UfqHRD0Z\n\
5SEcFcMQMzQEomJdGSQnyxAOLLCto3EwbzAdBgNVHQ4EFgQU1Kr6xJ204AU+VRUi\n\
LcmhJ+WHJdEwHwYDVR0jBBgwFoAU1Kr6xJ204AU+VRUiLcmhJ+WHJdEwDwYDVR0T\n\
AQH/BAUwAwEB/zAcBgNVHREEFTAToBEGCCsGAQUFBwgIoAUMAyouYTAKBggqhkjO\n\
PQQDAgMkADAhAg5bDZ3kugFqfLXhOEtSqQIPAJ4dkePkSuUBvLJNGuRX\n\
-----END CERTIFICATE-----");

    /* /CN=test otherName 1.3.6.1.5.5.7.8.8;UTF8 *. (NAIRealm)*/
    X509 *certnairealmillegalshort = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBRTCCAQ+gAwIBAgIUfQvgCc2mVD0Ku/lrcbS6xyD4Z10wCgYIKoZIzj0EAwIw\n\
DzENMAsGA1UEAwwEdGVzdDAeFw0yNDEwMDgxNzMyMzVaFw0yNDExMDcxNzMyMzVa\n\
MA8xDTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAR2CrK5OJ9A\n\
BtZOKXwZerLxgsZtZpFXZNG39cP7o3AwbjAdBgNVHQ4EFgQUw4/2JS93DsmvHef0\n\
3b8c7unZ+bswHwYDVR0jBBgwFoAUw4/2JS93DsmvHef03b8c7unZ+bswDwYDVR0T\n\
AQH/BAUwAwEB/zAbBgNVHREEFDASoBAGCCsGAQUFBwgIoAQMAiouMAoGCCqGSM49\n\
BAMCAyQAMCECDwCjFlLVSKHmDjIx3TmVNAIONhlWmvGXic+uxXH4w50=\n\
-----END CERTIFICATE-----");

    /* /CN=test otherName 1.3.6.1.5.5.7.8.8;UTF8 test.local,*.test.local (NAIRealm)*/
    X509 *certnairealmmulti = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBazCCATWgAwIBAgIUWBGwOKr2cNTjV9SmLCkh7aNjqJ0wCgYIKoZIzj0EAwIw\n\
DzENMAsGA1UEAwwEdGVzdDAeFw0yNDEwMDgxNzM1NTNaFw0yNDExMDcxNzM1NTNa\n\
MA8xDTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAAQl2LZC8279\n\
+fRJR6/Bj6L9jplqjxKdGzf4Nr1ro4GVMIGSMB0GA1UdDgQWBBQiEUakbMViqxOo\n\
q0ilLVC3LnPgezAfBgNVHSMEGDAWgBQiEUakbMViqxOoq0ilLVC3LnPgezAPBgNV\n\
HRMBAf8EBTADAQH/MD8GA1UdEQQ4MDagGAYIKwYBBQUHCAigDAwKdGVzdC5sb2Nh\n\
bKAaBggrBgEFBQcICKAODAwqLnRlc3QubG9jYWwwCgYIKoZIzj0EAwIDJAAwIQIO\n\
cTdHMyy8Il3kKRoYTacCDwDCpnRnB7g3A9M/84PsCQ==\n\
-----END CERTIFICATE-----");

    /* /CN=test otherName 1.3.6.1.5.5.7.8.8;UTF8 other.local (NAIRealm), DNS test.local*/
    X509 *certnairealmanddns = getcert("-----BEGIN CERTIFICATE-----\n\
MIIBWzCCASagAwIBAgIUVsLEa/cJPjQuaro+KRH0GJfOW0QwCgYIKoZIzj0EAwIw\n\
DzENMAsGA1UEAwwEdGVzdDAeFw0yNDEwMTAxMjI3MzNaFw0yNDExMDkxMjI3MzNa\n\
MA8xDTALBgNVBAMMBHRlc3QwMjAQBgcqhkjOPQIBBgUrgQQABgMeAASYGDrMtP4F\n\
m3l60VVPWNtz/kkJ7bbk5LLvmmGLo4GGMIGDMB0GA1UdDgQWBBTt0867K5xuwqi0\n\
TX863ZHqYpPcWjAfBgNVHSMEGDAWgBTt0867K5xuwqi0TX863ZHqYpPcWjAPBgNV\n\
HRMBAf8EBTADAQH/MDAGA1UdEQQpMCegGQYIKwYBBQUHCAigDQwLb3RoZXIubG9j\n\
YWyCCnRlc3QubG9jYWwwCgYIKoZIzj0EAwIDIwAwIAIODwGo3Yvn1o+h8/bVL9QC\n\
Djxuj56ZZL9t3+OVveS6\n\
-----END CERTIFICATE-----");

    memset(&conf, 0, sizeof(conf));
    conf.hostports = list_create();

    debug_init("t_verify_cert");
    debug_set_level(5);

    /* test check disabled*/
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 0;
        hp.host = "test";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsimple, &conf, &hp, NULL), "check disabled");

        while (list_shift(conf.hostports))
            ;
    }

    /* test no check if prefixlen != 255 (CIDR) */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        hp.host = "0.0.0.0/0";
        hp.prefixlen = 0;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsimple, &conf, &hp, NULL), "cidr prefix");

        while (list_shift(conf.hostports))
            ;
    }

    /* test simple match for CN=test */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        hp.host = "test";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        /* RFC 9525 deprecated CN check, only check in legacy mode*/
        conf.certcncheck = 1;
        ok(1, verifyconfcert(certsimple, &conf, &hp, NULL), "simple cert cn legacy");
        conf.certcncheck = 0;

        ok(0, verifyconfcert(certsimple, &conf, &hp, NULL), "simple cert cn");
        ok(0, verifyconfcert(certsimpleother, &conf, &hp, NULL), "negative simple cert cn");

        /* as per RFC 6125 6.4.4: CN MUST NOT be matched if SAN is present */
        ok(0, verifyconfcert(certsandns, &conf, &hp, NULL), "simple cert cn vs san dns, RFC6125");

        while (list_shift(conf.hostports))
            ;
    }

    /* test literal ip match to SAN IP */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        hp.host = "192.0.2.1";
        getaddrinfo(hp.host, NULL, NULL, &hp.addrinfo);
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsanip, &conf, &hp, NULL), "san ip");
        ok(0, verifyconfcert(certsanipother, &conf, &hp, NULL), "wrong san ip");
        ok(0, verifyconfcert(certsimple, &conf, &hp, NULL), "negative san ip");
        ok(1, verifyconfcert(certsanipindns, &conf, &hp, NULL), "san ip in dns");
        ok(1, verifyconfcert(certcomplex, &conf, &hp, NULL), "san ip in complex cert");

        freeaddrinfo(hp.addrinfo);
        while (list_shift(conf.hostports))
            ;
    }

    /* test literal ipv6 match to SAN IP */
    {
        struct hostportres hp;
        memset(&hp, 0, sizeof(struct hostportres));

        conf.name = "test";
        conf.certnamecheck = 1;
        hp.host = "2001:db8::1";
        getaddrinfo(hp.host, NULL, NULL, &hp.addrinfo);
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsanipv6, &conf, &hp, NULL), "san ipv6");
        ok(0, verifyconfcert(certsanipother, &conf, &hp, NULL), "wrong san ipv6");
        ok(0, verifyconfcert(certsimple, &conf, &hp, NULL), "negative san ipv6");
        ok(1, verifyconfcert(certsanipv6indns, &conf, &hp, NULL), "san ipv6 in dns");
        ok(1, verifyconfcert(certcomplex, &conf, &hp, NULL), "san ipv6 in complex cert");

        freeaddrinfo(hp.addrinfo);
        while (list_shift(conf.hostports))
            ;
    }

    /* test simple match for SAN DNS:test.local */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        hp.host = "test.local";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsandns, &conf, &hp, NULL), "san dns");
        ok(0, verifyconfcert(certsandnsother, &conf, &hp, NULL), "negative san dns");
        ok(1, verifyconfcert(certcomplex, &conf, &hp, NULL), "san dns in complex cert");
        ok(0, verifyconfcert(certsimple, &conf, &hp, NULL), "missing san dns");

        while (list_shift(conf.hostports))
            ;
    }

    /* test SAN DNS upper case*/
    {
        struct hostportres hp;

        conf.name = "TEST";
        conf.certnamecheck = 1;
        hp.host = "TEST";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        /* RFC 9525 deprecated CN check, only check in legacy mode*/
        conf.certcncheck = 1;
        ok(1, verifyconfcert(certsimple, &conf, &hp, NULL), "CN upper case legacy");
        conf.certcncheck = 0;

        ok(0, verifyconfcert(certsimple, &conf, &hp, NULL), "CN upper case");

        hp.host = "TEST.local";
        ok(1, verifyconfcert(certsandns, &conf, &hp, NULL), "san dns upper case");

        while (list_shift(conf.hostports))
            ;
    }

    /* test wildcard in san dns */
    {
        struct hostportres hp;
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);
        conf.name = "test";
        conf.certnamecheck = 1;

        hp.host = "some.test.local";
        ok(1, verifyconfcert(certwildcard, &conf, &hp, NULL), "san dns wildcard");
        ok(0, verifyconfcert(certpartialwildcard, &conf, &hp, NULL), "wrong san dns partial wildcard");
        hp.host = "some.test.other";
        ok(0, verifyconfcert(certwildcard, &conf, &hp, NULL), "wrong san dns wildcard base");
        hp.host = "some.sub.test.local";
        ok(0, verifyconfcert(certwildcard, &conf, &hp, NULL), "wrong san dns wildcard subsubdomain");
        ok(0, verifyconfcert(certmultiwildcard, &conf, &hp, NULL), "wrong san dns multiple wildcard");

        while (list_shift(conf.hostports))
            ;
    }

    /* test multiple hostports san dns(match in second) */
    {
        struct hostportres hp1, hp2;

        conf.name = "test";
        conf.certnamecheck = 1;
        hp1.host = "test.none";
        hp1.prefixlen = 255;
        list_push(conf.hostports, &hp1);
        hp2.host = "test";
        hp2.prefixlen = 255;
        list_push(conf.hostports, &hp2);

        /* RFC 9525 deprecated CN check, only check in legacy mode*/
        conf.certcncheck = 1;
        ok(1, verifyconfcert(certsimple, &conf, NULL, NULL), "multi hostport cn legacy");
        conf.certcncheck = 0;

        ok(0, verifyconfcert(certsimple, &conf, NULL, NULL), "multi hostport cn");
        ok(0, verifyconfcert(certsimpleother, &conf, NULL, NULL), "negative multi hostport cn");

        while (list_shift(conf.hostports))
            ;
    }

    /* test multiple hostports san dns(match in second) */
    {
        struct hostportres hp1, hp2;

        conf.name = "test";
        conf.certnamecheck = 1;
        hp1.host = "test.none";
        hp1.prefixlen = 255;
        list_push(conf.hostports, &hp1);
        hp2.host = "test.local";
        hp2.prefixlen = 255;
        list_push(conf.hostports, &hp2);

        ok(1, verifyconfcert(certsandns, &conf, NULL, NULL), "multi hostport san dns");
        ok(0, verifyconfcert(certsandnsother, &conf, NULL, NULL), "negative multi hostport san dns");
        ok(1, verifyconfcert(certcomplex, &conf, NULL, NULL), "multi hostport san dns in complex cert");

        ok(0, verifyconfcert(certsandns, &conf, &hp1, NULL), "multi hostport explicit wrong cert");
        ok(1, verifyconfcert(certsandns, &conf, &hp2, NULL), "multi hostport explicit matching cert");
        ok(0, verifyconfcert(certcomplex, &conf, &hp1, NULL), "multi hostport explicit wrong complex cert");
        ok(1, verifyconfcert(certcomplex, &conf, &hp2, NULL), "multi hostport explicit matching complex cert");

        while (list_shift(conf.hostports))
            ;
    }

    /* test explicit CN regex */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "CN:/t..t/"), "explicit cn regex config");

        ok(1, verifyconfcert(certsimple, &conf, NULL, NULL), "explicit cn regex");
        ok(0, verifyconfcert(certsimpleother, &conf, NULL, NULL), "negative explicit cn regex");
        ok(1, verifyconfcert(certsandns, &conf, NULL, NULL), "explicit cn regex with SAN DNS");

        freematchcertattr(&conf);
    }

    /* test explicit ip match to SAN IP */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "SubjectAltName:IP:192.0.2.1"), "explicit san ip config");

        ok(1, verifyconfcert(certsanip, &conf, NULL, NULL), "explicit san ip");
        ok(0, verifyconfcert(certsanipother, &conf, NULL, NULL), "wrong explicit san ip");
        ok(0, verifyconfcert(certsimple, &conf, NULL, NULL), "missing explicit san ip");
        ok(1, verifyconfcert(certcomplex, &conf, NULL, NULL), "explicit san ip in complex cert");

        freematchcertattr(&conf);
    }

    /* test explicit ipv6 match to SAN IP */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "SubjectAltName:IP:2001:db8::1"), "explicit san ipv6 config");

        ok(1, verifyconfcert(certsanipv6, &conf, NULL, NULL), "explicit san ipv6");
        ok(0, verifyconfcert(certsanipother, &conf, NULL, NULL), "wrong explicit san ipv6");
        ok(0, verifyconfcert(certsimple, &conf, NULL, NULL), "missing explicitsan ipv6");
        ok(1, verifyconfcert(certcomplex, &conf, NULL, NULL), "explicit san ipv6 in complex cert");

        freematchcertattr(&conf);
    }

    /* test explicit SAN DNS regex */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "SubjectAltName:DNS:/t..t\\.local/"), "explicit san dns regex config");

        ok(1, verifyconfcert(certsandns, &conf, NULL, NULL), "explicit san dns");
        ok(0, verifyconfcert(certsandnsother, &conf, NULL, NULL), "negative explicit san dns");
        ok(0, verifyconfcert(certsimple, &conf, NULL, NULL), "missing explicit san dns");
        ok(1, verifyconfcert(certcomplex, &conf, NULL, NULL), "explicit san dns in complex cert");

        freematchcertattr(&conf);
    }

    /* test explicit SAN URI regex */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "SubjectAltName:URI:/https:\\/\\/test.local\\/profile#me/"), "explicit cn regex config");

        ok(1, verifyconfcert(certsanuri, &conf, NULL, NULL), "explicit san uri regex");
        ok(0, verifyconfcert(certsanuriother, &conf, NULL, NULL), "negative explicit san uri");
        ok(0, verifyconfcert(certsimple, &conf, NULL, NULL), "missing explicit san uri");

        freematchcertattr(&conf);
    }

    /* test explicit SAN rID */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "SubjectAltName:rID:1.2.3.4"), "explicit san rid config");

        ok(1, verifyconfcert(certsanrid, &conf, NULL, NULL), "explicit san rid");
        ok(0, verifyconfcert(certsanridother, &conf, NULL, NULL), "negative explicit san rid");
        ok(0, verifyconfcert(certsimple, &conf, NULL, NULL), "missing explicit san rid");

        freematchcertattr(&conf);
    }

    /* test explicit SAN otherNAME */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "SubjectAltName:otherName:1.3.6.1.5.5.7.8.8:/test.local/"), "explicit san otherName config");

        ok(1, verifyconfcert(certsanothername, &conf, NULL, NULL), "explicit san otherName");
        ok(0, verifyconfcert(certsanothernameother, &conf, NULL, NULL), "negative explicit san otherName");
        ok(0, verifyconfcert(certsimple, &conf, NULL, NULL), "missing explicit san otherName");

        freematchcertattr(&conf);
    }

    /* test valid config syntax */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(1, addmatchcertattr(&conf, "CN:/t..t"), "test regex config syntax");
        ok(1, verifyconfcert(certsimple, &conf, NULL, NULL), "test regex config syntax execution");

        freematchcertattr(&conf);
    }

    /* test invalid config syntax */
    {
        conf.name = "test";
        conf.certnamecheck = 0;

        ok(0, addmatchcertattr(&conf, "CN:t..t"), "test invalid syntax regex");
        freematchcertattr(&conf);

        ok(0, addmatchcertattr(&conf, "SAN:/t..t/"), "test invalid syntax attribute");
        freematchcertattr(&conf);

        ok(0, addmatchcertattr(&conf, "SubjectAltName:IP:1.2.3"), "test invalid syntax ip");
        freematchcertattr(&conf);

        ok(0, addmatchcertattr(&conf, "SubjectAltName:IP:2001:db8:1"), "test invalid syntax ipv6");
        freematchcertattr(&conf);

        ok(0, addmatchcertattr(&conf, "SubjectAltName:rID:1:2"), "test invalid syntax rID");
        freematchcertattr(&conf);
    }

    /* test explicit & implicit combined */
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 1;
        hp.host = "test.local";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, addmatchcertattr(&conf, "CN:/t..t"), "combined config");

        ok(1, verifyconfcert(certsandns, &conf, &hp, NULL), "combined san dns");
        ok(0, verifyconfcert(certsandnsother, &conf, &hp, NULL), "negative combined san dns");
        ok(1, verifyconfcert(certcomplex, &conf, &hp, NULL), "combined san dns in complex cert");
        ok(0, verifyconfcert(certsimple, &conf, &hp, NULL), "combined missing san dns");

        while (list_shift(conf.hostports))
            ;
        freematchcertattr(&conf);
    }

    /* test multiple explicit checks*/
    {
        struct hostportres hp;

        conf.name = "test";
        conf.certnamecheck = 0;
        hp.host = "test.local";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, addmatchcertattr(&conf, "SubjectAltName:DNS:/test\\.local/"), "multiple check 1");
        ok(1, addmatchcertattr(&conf, "SubjectAltName:rID:1.2.3.4"), "multiple check 2");

        ok(0, verifyconfcert(certsandns, &conf, &hp, NULL), "multiple missing rID");
        ok(0, verifyconfcert(certsanrid, &conf, &hp, NULL), "multiple missing DNS");
        ok(1, verifyconfcert(certmulti, &conf, &hp, NULL), "multiple SANs");
        ok(0, verifyconfcert(certmultiother, &conf, &hp, NULL), "multiple negative match");
        ok(0, verifyconfcert(certcomplex, &conf, &hp, NULL), "multiple missing rID in complex cert");
        ok(0, verifyconfcert(certsimple, &conf, &hp, NULL), "multiple missing everything");

        while (list_shift(conf.hostports))
            ;
        freematchcertattr(&conf);
    }

    /* test NAIrealm match from dynamic discovery*/
    {
        struct hostportres hp;
        char *nairealm = "test.local";
        char *naisubrealm = "sub.test.local";

        conf.name = "dynamic";
        conf.certnamecheck = 1;
        hp.host = "test.dynamic";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsanothername, &conf, &hp, nairealm), "dynamic NAI realm");
        ok(0, verifyconfcert(certsanothernameother, &conf, &hp, nairealm), "negative dynamic NAI realm");
        ok(0, verifyconfcert(certsanothername, &conf, &hp, naisubrealm), "negative dynamic NAI sub-realm");
        ok(1, verifyconfcert(certnairealmwildcard, &conf, &hp, nairealm), "dynamic NAI realm wildcard");
        ok(0, verifyconfcert(certnairealmwildcard, &conf, &hp, naisubrealm), "dynamic NAI realm wildcard subrealm");
        ok(0, verifyconfcert(certnairealmillegalwildcard, &conf, &hp, naisubrealm), "dynamic NAI realm illegal");
        ok(1, verifyconfcert(certnairealmmulti, &conf, &hp, nairealm), "dynamic NAI realm multi");
        ok(1, verifyconfcert(certnairealmmulti, &conf, &hp, naisubrealm), "dynamic NAI realm multi wildcard");

        /* test coerner cases*/
        ok(1, verifyconfcert(certnairealmshort, &conf, &hp, "a.a"), "dynamic NAI realm short");
        ok(0, verifyconfcert(certnairealmshort, &conf, &hp, "..a"), "dynamic NAI realm short illegal subrealm");
        ok(0, verifyconfcert(certnairealmillegalshort, &conf, &hp, "a."), "dynamic NAI realm short illegal");

        while (list_shift(conf.hostports))
            ;
    }

    /* test NAIrealm and DNS combined*/
    {
        struct hostportres hp;
        char *nairealm = "other.local";
        char *nairealmother = "other.other";

        conf.name = "dynamic";
        conf.certnamecheck = 1;
        hp.host = "test.local";
        hp.prefixlen = 255;
        list_push(conf.hostports, &hp);

        ok(1, verifyconfcert(certsandns, &conf, &hp, nairealm), "non-NAI realm and DNS");
        ok(0, verifyconfcert(certsandnsother, &conf, &hp, nairealm), "negative NAI realm match in SANDNS");
        ok(1, verifyconfcert(certnairealmanddns, &conf, &hp, nairealmother), "match DNS even if NAIrealm fails");
        hp.host = "test.other";
        ok(1, verifyconfcert(certnairealmanddns, &conf, &hp, nairealm), "match NAIrealm even if DNS fails");

        while (list_shift(conf.hostports))
            ;
    }

    printf("1..%d\n", numtests);
    list_free(conf.hostports);
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
    X509_free(certsanuri);
    X509_free(certsanuriother);
    X509_free(certsanrid);
    X509_free(certsanridother);
    X509_free(certsanothername);
    X509_free(certsanothernameother);
    X509_free(certmulti);
    X509_free(certmultiother);
    X509_free(certwildcard);
    X509_free(certmultiwildcard);
    X509_free(certpartialwildcard);

    return 0;
}
