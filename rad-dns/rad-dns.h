#ifndef _RAD_DNS_H
#define _RAD_DNS_H

#include <ares.h>
#include <stdbool.h>

struct callback_data
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

int dns_main(char *host,int fd1);
int init_ares();
void wait_ares(ares_channel channel);
void srv_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);
void naptr_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);

#endif