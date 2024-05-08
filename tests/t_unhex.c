/* Copyright (C) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include "../gconfig.h"
#include "../util.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printhex(uint8_t *str, size_t len) {
    int i = 0;
    for (; i < len; i++) {
        printf("%02x", str[i]);
    }
}

static int
_check_unhex(char *input, uint8_t process_null, uint8_t *expected, size_t expected_len) {
    int result = 1;
    int length = 0;
    char *str = stringcopy(input, 0);

    if (strlen(input) < expected_len) {
        printf("unhex error: expected length can't longer than input length\n");
        return 0;
    }

    length = unhex(str, process_null);

    if (length != expected_len) {
        printf("unhex: expected length %zu, was %d\n", expected_len, length);
        result = 0;
    }
    if (memcmp(str, expected, expected_len) != 0) {
        result = 0;
        printf("unhex: expected string ");
        printhex(expected, expected_len);
        printf(", was ");
        printhex((uint8_t *)str, expected_len);
        printf("\n");
    }
    free(str);
    return result;
}

int main(int argc, char *argv[]) {
    int testcount = 0;

    {
        char *input = "test";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - simple test with no hex\n", ++testcount);
    }

    {
        char *input = "test%01";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x01};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - simple hex\n", ++testcount);
    }

    {
        char *input = "test%01t";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x01, 0x74};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - simple hex with following char\n", ++testcount);
    }

    {
        char *input = "test%01%02";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x01, 0x02};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - two hex\n", ++testcount);
    }

    {
        char *input = "test%01%02t";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x01, 0x02, 0x74};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - two hex with flollowing char\n", ++testcount);
    }

    {
        char *input = "test%01t%02t";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x01, 0x74, 0x02, 0x74};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - two hex with flollowing char\n", ++testcount);
    }

    {
        char *input = "test%xy";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x25, 0x78, 0x79};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - not hex\n", ++testcount);
    }

    {
        char *input = "test%0g";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x25, 0x30, 0x67};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - not hex 2\n", ++testcount);
    }

    {
        char *input = "test%0";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x25, 0x30};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - too short\n", ++testcount);
    }

    {
        char *input = "test%xy";
        uint8_t expect[] = {0x74, 0x65, 0x73, 0x74, 0x25, 0x78, 0x79};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - not hex\n", ++testcount);
    }

    {
        char *input = "%01";
        uint8_t expect[] = {0x01};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - start hex\n", ++testcount);
    }

    {
        char *input = "%01a";
        uint8_t expect[] = {0x01, 0x61};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - start hex with following char\n", ++testcount);
    }

    {
        char *input = "%00";
        uint8_t expect[] = {0x25, 0x30, 0x30};
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - skip zero\n", ++testcount);
    }

    {
        char *input = "%00";
        uint8_t expect[] = {0x00};
        if (!_check_unhex(input, 1, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - convert zero\n", ++testcount);
    }

    {
        char *input = "%";
        uint8_t expect[] = {0x25};
        if (!_check_unhex(input, 1, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hex zero length\n", ++testcount);
    }

    {
        char *input = "%%";
        uint8_t expect[] = {0x00}; //actually zero length
        if (!_check_unhex(input, 0, expect, 0))
            printf("not ");
        printf("ok %d - hexstring zero length\n", ++testcount);
    }

    {
        char *input = "%%01";
        uint8_t expect[] = {0x01}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring length one\n", ++testcount);
    }

    {
        char *input = "%%0102";
        uint8_t expect[] = {0x01, 0x02}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring length two\n", ++testcount);
    }

    {
        char *input = "%%0102030405060708090a0b0c0d0e0f10";
        uint8_t expect[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring long\n", ++testcount);
    }

    {
        char *input = "te%%0102st";
        uint8_t expect[] = {0x74, 0x65, 0x01, 0x02, 0x73, 0x74}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring leader and trailer\n", ++testcount);
    }

    {
        char *input = "%%01x";
        uint8_t expect[] = {0x01, 0x78}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring terminate\n", ++testcount);
    }

    {
        char *input = "%%01ax";
        uint8_t expect[] = {0x01, 0x61, 0x78}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring terminate\n", ++testcount);
    }

    {
        char *input = "%%01x%%01";
        uint8_t expect[] = {0x01, 0x78, 0x01}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring two strings\n", ++testcount);
    }

    {
        char *input = "%%01%%01";
        uint8_t expect[] = {0x01, 0x01}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring two strings no ascii\n", ++testcount);
    }

    {
        char *input = "%%0000";
        uint8_t expect[] = {0x00, 0x00}; //actually zero length
        if (!_check_unhex(input, 1, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring zeroes\n", ++testcount);
    }

    {
        char *input = "%%01%01";
        uint8_t expect[] = {0x01, 0x01}; //actually zero length
        if (!_check_unhex(input, 0, expect, sizeof(expect)))
            printf("not ");
        printf("ok %d - hexstring and hexchar mixed\n", ++testcount);
    }

    printf("1..%d\n", testcount);
    return 0;
}
