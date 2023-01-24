/* Copyright (C) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../radmsg.h"

int numtests = 0;

void test_radlen(uint8_t *buf, int expected, char *msg) {
    int actual = get_checked_rad_length(buf);

    if (actual != expected)
        printf ("not ");
    printf("ok %d - radlen %s (expected %d, got %d)\n", ++numtests, msg, expected, actual);
}

int
main (int argc, char *argv[])
{
    {
        uint8_t buf[] = {0x0c, 0x00, 0x00, 0x2a};
        test_radlen(buf, 42, "basic length test");
    }

    {
        uint8_t buf[] = {0x0c, 0x00, 0x00, 0x14};
        test_radlen(buf, 20, "lower bound");
    }
    
    {
        uint8_t buf[] = {0x0c, 0x00, 0x10, 0x00};
        test_radlen(buf, 4096, "upper bound");

    }

    {
        uint8_t buf[] = {0x0c, 0x00, 0x00, 0x13};
        test_radlen(buf, -19, "too small");
    }

    {
        uint8_t buf[] = {0x0c, 0x00, 0x10, 0x01};
        test_radlen(buf, -4097, "too big");
    }

    {
        uint8_t buf[] = {0x0c, 0x00, 0x00, 0x00};
        test_radlen(buf, 0, "zero");
    }

    printf ("1..%d\n", numtests);
}
