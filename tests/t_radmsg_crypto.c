#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <../debug.h>
#include <../utilcrypto.h>

/* this is not to test digest functions extensively, but to ensure OpenSSL digest APIs are called correctly */

/* dummy values*/
uint8_t *shared = (uint8_t *)"secret";
uint8_t sharedlen = 6;
uint8_t auth[] = {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"};
uint8_t salt[] = {"\x12\x34"};

int numtests = 0;

void test_crypto_cycle(char *clear, char *encrypted, uint8_t len, uint8_t *salt, uint8_t saltlen, char *text) {
    uint8_t input[len];

    numtests++;
    memcpy(input, clear, len);

    if (!pwdcrypt(1, input, len, shared, sharedlen, auth, salt, saltlen)) {
        printf("not ok %d - %s: pwdcrypt returned 0\n", numtests, text);
        return;
    }
    if (memcmp(input, encrypted, len) != 0) {
        printf("not ok %d - %s: encrypt\n", numtests, text);
        return;
    }

    if (!pwdcrypt(0, input, len, shared, sharedlen, auth, salt, saltlen)) {
        printf("not ok %d - %s: pwdcrypt returned 0\n", numtests, text);
        return;
    }
    if (memcmp(input, clear, len) != 0) {
        printf("not ok %d - %s: decrypt\n", numtests, text);
        return;
    }
    printf("ok %d - %s\n", numtests, text);
    return;
}

void test_radmsgsign(uint8_t *packet, uint8_t *expected, size_t len, uint8_t *rqauth, char *test) {
    uint8_t buf[20];
    memcpy(buf, packet, 20);

    if (radmsgsign(buf, 20, shared, sharedlen, NULL, rqauth) == 0)
        printf("not ok %d - %s radmsgsign returned 0\n", ++numtests, test);
    else if (memcmp(buf, expected, 20) != 0)
        printf("not ok %d - %s radmsgsign not updated correctly\n", ++numtests, test);
    else
        printf("ok %d - %s radmsgsign\n", ++numtests, test);
}

int main(int argc, char *argv[]) {

    debug_init("t_crypto");
    debug_set_level(5);

    test_crypto_cycle("password\0\0\0\0\0\0\0\0",
                      "\x17\x22\xd2\xd5\xff\x46\x48\x5c\x32\x78\x86\x60\x9f\x6e\xd8\x24",
                      16, NULL, 0, "short password");

    test_crypto_cycle("passwordpasswordpasswordpassword",
                      "\x17\x22\xd2\xd5\xff\x46\x48\x5c\x42\x19\xf5\x13\xe8\x01\xaa\x40\x82\x6a\xb8\xa8\xe8\xc9\x80\xe8\xd0\xac\x84\xb9\x85\xec\xc3\x6a",
                      32, NULL, 0, "long password");

    test_crypto_cycle("\x10MS-MPPE-Send-Key\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                      "\x6c\xfe\x33\x27\xf8\xf7\xac\x60\xf9\x3e\x10\xe5\x4a\x1b\x1b\x85\x16\xb0\x66\xce\x50\xb0\xf1\x5d\x16\xb8\x3a\xe4\x53\x3f\x45\xc1",
                      32, salt, 2, "password with salt");

    {
        if (pwdcrypt(1, (uint8_t *)"password", 8, shared, sharedlen, auth, NULL, 0) == 0)
            printf("ok %d - passowrd too short\n", ++numtests);
        else
            printf("not ok %d - password too short\n", ++numtests);
    }

    {
        if (pwdcrypt(1, (uint8_t *)"\x12\x34\x10MS-MPPE-Send-Key\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 18, shared, sharedlen, auth, salt, 2) == 0)
            printf("ok %d - wrongly include salt in buffer\n", ++numtests);
        else
            printf("not ok %d - wrongly include salt in buffer\n", ++numtests);
    }

    {
        uint8_t *packet = (uint8_t *)"\x0c\x00\x00\x14\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
        test_radmsgsign(packet, packet, 20, NULL, "status-server");
    }

    test_radmsgsign((uint8_t *)"\x04\x01\x00\x14\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
                    (uint8_t *)"\x04\x01\x00\x14\xdf\x0a\x38\x46\xaf\xf3\xa2\x9a\x8d\x50\x1c\x9f\xc3\x3e\x7c\xae",
                    20, NULL, "accounting-request");

    test_radmsgsign((uint8_t *)"\x02\x02\x00\x14\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                    (uint8_t *)"\x02\x02\x00\x14\x7b\xac\x77\xb8\xc4\xf6\xb8\x50\x50\x9c\x6f\x89\xd1\xb2\xe9\x4c",
                    20, auth, "access-accept");

    printf("1..%d\n", numtests);

    return 0;
}
