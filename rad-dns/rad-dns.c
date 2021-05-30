#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include "rad-dns.h"

void naptr_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
    struct callback_data *data = (struct callback_data *)arg;
    if (status == ARES_SUCCESS)
    {
        struct ares_naptr_reply *reply;
        ares_parse_naptr_reply(abuf, alen, &reply);
        data->ptr = reply;
        while (reply != NULL)
        {
            if (!strncmp((char *)reply->service, "x-eduroam:radius.tls", sizeof "x-eduroam:radius.tls"))
            {
                data->msg = (char **)reply->replacement;
                data->empty = false;
                return;
            }
            reply = reply->next;
        }
        return;
    }
}

void srv_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
    struct callback_data *data = (struct callback_data *)arg;
    int i, j;
    unsigned short key;
    if (status == ARES_SUCCESS)
    {
        struct ares_srv_reply *reply;
        ares_parse_srv_reply(abuf, alen, &reply);
        data->ptr = reply;
        size_t count = 0;
        size_t largest_string = 40;
        struct ares_srv_reply *tmp_reply = reply;
        while (tmp_reply != NULL)
        {
            count++;
            tmp_reply = tmp_reply->next;
        }
        char **hosts = malloc(count * 8);
        unsigned short **ports = malloc(count * 8);
        unsigned short priority[count];
        tmp_reply = reply;
        for (i = 0; i < count; i++)
        {
            hosts[i] = tmp_reply->host;
            ports[i] = &tmp_reply->port;
            priority[i] = tmp_reply->weight;
            tmp_reply = tmp_reply->next;
        }
        char *host_key;
        unsigned short *ports_key;
        for (i = 1; i < count; i++)
        {
            key = priority[i];
            host_key = hosts[i];
            ports_key = ports[i];
            j = i - 1;

            while (j >= 0 && priority[j] > key)
            {
                priority[j + 1] = priority[j];
                hosts[j + 1] = hosts[j];
                ports[j + 1] = ports[j];
                j = j - 1;
            }
            priority[j + 1] = key;
            hosts[j + 1] = host_key;
            ports[j + 1] = ports_key;
        }

        data->msg = hosts;
        data->ports = ports;
        data->count = count;
        data->str_len = largest_string;
        data->empty = false;
    }
}

void wait_ares(ares_channel channel)
{
    for (;;)
    {
        struct timeval *tvp, tv;
        fd_set read_fds, write_fds;
        int nfds;

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0)
        {
            break;
        }
        tvp = ares_timeout(channel, NULL, &tv);
        select(nfds, &read_fds, &write_fds, NULL, tvp);
        ares_process(channel, &read_fds, &write_fds);
    }
}

int init_ares()
{
    if (ares_library_init(ARES_LIB_INIT_ALL) != 0)
    {
        return -1;
    }
    return 0;
}

int dns_main(char *host, int fd1)
{
    int i;
    if (ares_library_initialized() != ARES_SUCCESS)
    {
        return -1;
    }
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
    options.timeout = 5;
    optmask |= ARES_OPT_TIMEOUT;

    if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
    {
        return -1;
    }
    struct callback_data *naptr_data = malloc(sizeof *naptr_data);
    naptr_data->empty = true;
    struct callback_data *srv_data = malloc(sizeof *srv_data);
    srv_data->empty = true;
    ares_query(channel, host, ns_c_in, ns_t_naptr, &naptr_callback, naptr_data);
    wait_ares(channel);
    if (naptr_data->empty)
    {
        free(naptr_data);
        free(srv_data);
        return -1;
    }
    ares_query(channel, (char *)naptr_data->msg, ns_c_in, ns_t_srv, &srv_callback, srv_data);
    wait_ares(channel);
    if (srv_data->empty)
    {
        free(naptr_data);
        free(srv_data);
        return -1;
    }
    char buffer[srv_data->count * srv_data->str_len + 255];
    int cx = 0;
    cx += snprintf(buffer, srv_data->count * srv_data->str_len + 255, "server dynamic_radsec.%s {\n", host);
    for (i = 0; i < srv_data->count; i++)
    {
        cx += snprintf(buffer + cx, srv_data->count * srv_data->str_len + 255 - cx, "\thost %s:%hu\n", srv_data->msg[i], *srv_data->ports[i]);
    }
    snprintf(buffer + cx, srv_data->count * srv_data->str_len + 255 - cx, "\ttype TLS\n}\n");
    write(fd1, buffer, strlen(buffer));

    //cleanup
    free(srv_data->msg);
    free(srv_data->ports);

    ares_free_data(naptr_data->ptr);
    ares_free_data(srv_data->ptr);

    free(naptr_data);
    free(srv_data);
    ares_destroy(channel);

    return 0;
}