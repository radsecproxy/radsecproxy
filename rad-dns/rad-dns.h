/* Copyright (c) 2021, Long Yang Paffrath <paffrath@yangnet.de>*/
/* See LICENSE for licensing information */

#ifndef _RAD_DNS_H
#define _RAD_DNS_H

#include <ares.h>
#include <stdbool.h>

struct naptr_callback_data
{
    /*true if there is not data to read*/
    bool empty;
    /*service tag to filter for*/
    char *service_tag;
    /*string or array of strings*/
    char **msg;
    /*pointer to ares object for later freeing*/
    void *ptr;
};

struct srv_callback_data
{
    /*true if there is no other data to read.*/
    bool empty;
    /*string or array of strings*/
    char **msg;
    /*array of ports*/
    unsigned short **ports;
    /*pointer to ares object for later freeing*/
    void *ptr;
    /*count of array if msg is an array ignore if not*/
    size_t count;
    /*max len of string in msg*/
    size_t str_len;
};

int dns_main(char *host, char *servicetag, int fd1);
int init_ares();
void wait_ares(ares_channel channel);
void srv_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);
void naptr_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);

#endif