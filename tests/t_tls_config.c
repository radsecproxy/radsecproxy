#include <stdio.h>
#include <stdint.h>
#include <limits.h>
//#include "../tlscommon.h"
#include <openssl/ssl.h>

extern int conf_tls_version(uint8_t dtls, const char *version, int *min, int *max);

int testcount = 0;

void test_tls_version(uint8_t dtls, char *config, int expect_ok, int expect_min, int expect_max, char *test) {
    int min, max = INT_MAX;
    int result;

    result = conf_tls_version(dtls, config, &min, &max);

    if (result == expect_ok && min == expect_min && max == expect_max)
        printf("ok %d - %s\n", ++testcount, test);
    else
        printf("not ok %d - %s, %s, %s, %s\n", ++testcount, test,
               result == expect_ok ? "returnvalue ok" : "wrong return value",
               min == expect_min ? "ok min" : "wrong min",
               max == expect_max ? "ok max" : "wrong max");
}

int main(int argc, char *argv[]) {

    test_tls_version(0, ":", 1, 0, 0, "all versions tls");
    test_tls_version(1, ":", 1, 0, 0, "all versions dtls");

    test_tls_version(0, "", 1, 0, 0, "test empty string");

    test_tls_version(0, ":TLS1_2", 1, 0, TLS1_2_VERSION, "max TLS1.2");
    test_tls_version(0, "TLS1_2:", 1, TLS1_2_VERSION, 0, "min TLS1.2");
    test_tls_version(0, "TLS1_1:TLS1_2", 1, TLS1_1_VERSION, TLS1_2_VERSION, "TLS1.1 to TLS1.2");
    test_tls_version(0, "TLS1_2:TLS1_1", 0, TLS1_2_VERSION, TLS1_1_VERSION, "TLS1.2 to TLS1.1");
    test_tls_version(0, "TLS1_2", 1, TLS1_2_VERSION, TLS1_2_VERSION, "exact TLS1.2");
    test_tls_version(0, "foo", 0, -1, -1, "illegal version foo");

    test_tls_version(1, ":DTLS1_2", 1, 0, DTLS1_2_VERSION, "max DTLS1.2");
    test_tls_version(1, "DTLS1_2:", 1, DTLS1_2_VERSION, 0, "min DTLS1.2");
    test_tls_version(1, "DTLS1:DTLS1_2", 1, DTLS1_VERSION, DTLS1_2_VERSION, "DTLS1 to DTLS1.2");
    test_tls_version(1, "DTLS1_2:DTLS1", 0, DTLS1_2_VERSION, DTLS1_VERSION, "DTLS1.2 to DTLS1");
    test_tls_version(1, "DTLS1_2", 1, DTLS1_2_VERSION, DTLS1_2_VERSION, "exact TLS1.2");
    test_tls_version(1, "TLS1_2", 0, -1, -1, "DTLS illegal version TLS1.2");

    printf("1..%d\n", testcount);
}
