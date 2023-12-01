/* Copyright (C) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <string.h>
#include "../util.h"

int
main (int argc, char *argv[])
{
    int testcount = 0;

    {
        char *str = "test";
        if (verifyutf8((uint8_t *)str, strlen(str)) != 1)
            printf("not ");
        printf("ok %d - simple test ascii\n", ++testcount);
    }

    {
        char *str = "smile 😀";
        if (verifyutf8((uint8_t *)str, strlen(str)) != 1)
            printf("not ");
        printf("ok %d - original utf8 string\n", ++testcount);
    }

    {
        uint8_t str[] = {0x00, 'x', 0x00};
        if (verifyutf8(str, 2) != 0)
            printf("not ");
        printf("ok %d - simple test null char\n", ++testcount);
    }

    {
        uint8_t str[] = {0x01, 0x00};
        if (verifyutf8(str, 1) != 0)
            printf("not ");
        printf("ok %d - control characters first\n", ++testcount);
    }

    {
        uint8_t str[] = {0x1F, 0x00};
        if (verifyutf8(str, 1) != 0)
            printf("not ");
        printf("ok %d - control characters last\n", ++testcount);
    }

    {
        uint8_t str[] = {0x7F, 0x00};
        if (verifyutf8(str, 1) != 0)
            printf("not ");
        printf("ok %d - delete\n", ++testcount);
    }

    {
        uint8_t str[] = {'t', 0x00, 's', 't', 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - invalid 2nd char\n", ++testcount);
    }

    {
        uint8_t str[] = {'t', 'e', 0x00, 't', 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - invalid 3rd char\n", ++testcount);
    }

    {
        uint8_t str[] = {'t', 'e', 's', 0x00, 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - invalid 4th char\n", ++testcount);
    }

    {
        uint8_t str[] = {0x80, 0x00};
        if (verifyutf8(str, 1) != 0)
            printf("not ");
        printf("ok %d - invalid continuation single byte\n", ++testcount);
    }

    {
        uint8_t str[] = {0xFF, 0x00};
        if (verifyutf8(str, 1) != 0)
            printf("not ");
        printf("ok %d - invalid byte\n", ++testcount);
    }

    {
        uint8_t str[] = {0xC2, 0xA0, 0x00};
        if (verifyutf8(str, 2) != 1)
            printf("not ");
        printf("ok %d - 2-byte char first codepoint\n", ++testcount);
    }

    {
        uint8_t str[] = {0xDF, 0xBF, 0x00};
        if (verifyutf8(str, 2) != 1)
            printf("not ");
        printf("ok %d - 2-byte char last codepoint\n", ++testcount);
    }

    {
        uint8_t str[] = {0xC0, 0x80, 0x00};
        if (verifyutf8(str, 2) != 0)
            printf("not ");
        printf("ok %d - overlong 1-byte\n", ++testcount);
    }

    {
        uint8_t str[] = {0xC2, 0x80, 0x00};
        if (verifyutf8(str, 2) != 0)
            printf("not ");
        printf("ok %d - 2-byte control first\n", ++testcount);
    }

    {
        uint8_t str[] = {0xC2, 0x9F, 0x00};
        if (verifyutf8(str, 2) != 0)
            printf("not ");
        printf("ok %d - 2-byte control last\n", ++testcount);
    }

    {
        uint8_t str[] = {0xE0, 0xA0, 0x80, 0x00};
        if (verifyutf8(str, 3) != 1)
            printf("not ");
        printf("ok %d - 3-byte char first codepoint\n", ++testcount);
    }

    {
        uint8_t str[] = {0xEF, 0xBF, 0xBF, 0x00};
        if (verifyutf8(str, 3) != 1)
            printf("not ");
        printf("ok %d - 3-byte char last codepoint\n", ++testcount);
    }

    {
        uint8_t str[] = {0xE0, 0x80, 0x80, 0x00};
        if (verifyutf8(str, 3) != 0)
            printf("not ");
        printf("ok %d - 3-byte char invalid 1\n", ++testcount);
    }

    {
        uint8_t str[] = {0xED, 0xA0, 0xBF, 0x00};
        if (verifyutf8(str, 3) != 0)
            printf("not ");
        printf("ok %d - 3-byte char invalid 2\n", ++testcount);
    }

    {
        uint8_t str[] = {0xF0, 0x90, 0x80, 0x80, 0x00};
        if (verifyutf8(str, 4) != 1)
            printf("not ");
        printf("ok %d - 4-byte char first codepoint\n", ++testcount);
    }

    {
        uint8_t str[] = {0xF4, 0x8F, 0xBF, 0xBF, 0x00};
        if (verifyutf8(str, 4) != 1)
            printf("not ");
        printf("ok %d - 4-byte char first codepoint\n", ++testcount);
    }

    {
        uint8_t str[] = {0xF0, 0x80, 0x80, 0x80, 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - 4-byte char invalid 1\n", ++testcount);
    }

    {
        uint8_t str[] = {0xF4, 0x90, 0x80, 0x80, 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - 4-byte char invalid 2\n", ++testcount);
    }

   {
        uint8_t str[] = {0xF7, 0xBF, 0xBF, 0xBF, 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - 4-byte char invalid 3\n", ++testcount);
    }

    {
        uint8_t str[] = {0xFF, 0xBF, 0xBF, 0xBF, 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - 4-byte char all ones\n", ++testcount);
    }

    {
        uint8_t str[] = {0xC2, 0x80, 0x00};
        if (verifyutf8(str, 1) != 0)
            printf("not ");
        printf("ok %d - 2-byte char too short\n", ++testcount);
    }

    {
        uint8_t str[] = {0xC2, 0x80, 0x80, 0x00};
        if (verifyutf8(str, 3) != 0)
            printf("not ");
        printf("ok %d - 2-byte char too long\n", ++testcount);
    }

    {
        uint8_t str[] = {0xC2, 0x80, 0x00, 0x00};
        if (verifyutf8(str, 3) != 0)
            printf("not ");
        printf("ok %d - invalid after 2-byte char\n", ++testcount);
    }

    {
        uint8_t str[] = {0xF0, 'x', 0x80, 0x80, 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - 4-byte char invalid continuation 2nd byte\n", ++testcount);
    }

    {
        uint8_t str[] = {0xF0, 0x90, 'x', 0x80, 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - 4-byte char invalid continuation 3rd byte\n", ++testcount);
    }

    {
        uint8_t str[] = {0xF0, 0x90, 0x80, 'x', 0x00};
        if (verifyutf8(str, 4) != 0)
            printf("not ");
        printf("ok %d - 4-byte char invalid continuation 4th byte\n", ++testcount);
    }

    {
        uint8_t str[] = {'t', 'e', 's', 't', 0xF0, 0x91, 0x82, 0x83, 'x', 'y', 'z', 0x00};
        if (verifyutf8(str, 11) != 1)
            printf("not ");
        printf("ok %d - long string\n", ++testcount);
    }

    printf("1..%d\n", testcount);
    return 0;
}
