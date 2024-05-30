/* Copyright (C) 2024, SWITCH */
/* See LICENSE for licensing information. */

#include "../debug.h"
#include "../radmsg.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

static int _check_eap(uint8_t *eap, size_t eap_len, int expected) {
    struct radmsg *msg = radmsg_init(RAD_Access_Request, 0, NULL);
    int result;

    while (eap_len > 0) {
        size_t len = eap_len > 253 ? 253 : eap_len;
        radmsg_add(msg, maketlv(RAD_Attr_EAP_Message, len, eap), 0);
        eap += len;
        eap_len -= len;
    }

    result = verifyeapformat(msg);
    radmsg_free(msg);
    return result == expected;
}

int main(int argc, char *argv[]) {
    int testcount = 0;

    debug_init("t_verify_eap");
    debug_set_level(5);

    {
        uint8_t eap[6];
        *(uint16_t *)&eap[2] = htons(sizeof(eap));

        if (!_check_eap(eap, sizeof(eap), 1))
            printf("not ");
        printf("ok %d - simple eap\n", ++testcount);
    }

    {
        uint8_t eap[4];
        *(uint16_t *)&eap[2] = htons(sizeof(eap));

        if (!_check_eap(eap, sizeof(eap), 1))
            printf("not ");
        printf("ok %d - minimum length\n", ++testcount);
    }

    {
        uint8_t eap[3];

        if (!_check_eap(eap, sizeof(eap), 0))
            printf("not ");
        printf("ok %d - too short\n", ++testcount);
    }

    {
        uint8_t eap[253];
        *(uint16_t *)&eap[2] = htons(sizeof(eap));

        if (!_check_eap(eap, sizeof(eap), 1))
            printf("not ");
        printf("ok %d - maxxed out attribute\n", ++testcount);
    }

    {
        uint8_t eap[254];
        *(uint16_t *)&eap[2] = htons(sizeof(eap));

        if (!_check_eap(eap, sizeof(eap), 1))
            printf("not ");
        printf("ok %d - mimimum overflow\n", ++testcount);
    }

    {
        uint8_t eap[10];
        *(uint16_t *)&eap[2] = htons(0);

        if (!_check_eap(eap, sizeof(eap), 0))
            printf("not ");
        printf("ok %d - eap length too short (all zero)\n", ++testcount);
    }

    {
        uint8_t eap[1024];
        *(uint16_t *)&eap[2] = htons(0);

        if (!_check_eap(eap, sizeof(eap), 0))
            printf("not ");
        printf("ok %d - eap length too short - very long eap\n", ++testcount);
    }

    {
        uint8_t eap[10];
        *(uint16_t *)&eap[2] = htons(255);

        if (!_check_eap(eap, sizeof(eap), 0))
            printf("not ");
        printf("ok %d - eap length too big\n", ++testcount);
    }

    {
        uint8_t eap[1024];
        *(uint16_t *)&eap[2] = htons(256);

        if (!_check_eap(eap, sizeof(eap), 0))
            printf("not ");
        printf("ok %d - eap length too big - very long eap\n", ++testcount);
    }

    {
        uint8_t eap[253];
        *(uint16_t *)&eap[2] = htons(sizeof(eap));

        struct radmsg *msg = radmsg_init(RAD_Access_Request, 0, NULL);
        radmsg_add(msg, maketlv(RAD_Attr_EAP_Message, sizeof(eap), eap), 0);
        radmsg_add(msg, maketlv(RAD_Attr_EAP_Message, 0, eap), 0);

        if (verifyeapformat(msg) != 0)
            printf("not ");
        printf("ok %d - zero length second attribute\n", ++testcount);
    }

    printf("1..%d\n", testcount);
    return 0;
}
