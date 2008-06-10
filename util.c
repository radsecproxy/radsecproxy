/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include "debug.h"

#if 0
#include <errno.h>
void errx(char *format, ...) {
    extern int errno;

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    if (errno) {
        fprintf(stderr, ": ");
        perror(NULL);
        fprintf(stderr, "errno=%d\n", errno);
    } else
        fprintf(stderr, "\n");
    exit(1);
}

void err(char *format, ...) {
    extern int errno;

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    if (errno) {
        fprintf(stderr, ": ");
        perror(NULL);
        fprintf(stderr, "errno=%d\n", errno);
    } else
        fprintf(stderr, "\n");
}
#endif

char *stringcopy(const char *s, int len) {
    char *r;
    if (!len)
	len = strlen(s);
    r = malloc(len + 1);
    if (!r)
	debug(DBG_ERR, "stringcopy: malloc failed");
    memcpy(r, s, len);
    r[len] = '\0';
    return r;
}

void printfchars(char *prefixfmt, char *prefix, char *charfmt, char *chars, int len) {
    int i;
    unsigned char *s = (unsigned char *)chars;
    if (prefix)
	printf(prefixfmt ? prefixfmt : "%s: ", prefix);
    for (i = 0; i < len; i++)
	printf(charfmt ? charfmt : "%c", s[i]);
    printf("\n");
}

char *addr2string(struct sockaddr *addr, socklen_t len) {
    struct sockaddr_in6 *sa6;
    struct sockaddr_in sa4;
    static char addr_buf[2][INET6_ADDRSTRLEN];
    static int i = 0;
    i = !i;
    if (addr->sa_family == AF_INET6) {
	sa6 = (struct sockaddr_in6 *)addr;
	if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
	    memset(&sa4, 0, sizeof(sa4));
	    sa4.sin_family = AF_INET;
	    sa4.sin_port = sa6->sin6_port;
	    memcpy(&sa4.sin_addr, &sa6->sin6_addr.s6_addr[12], 4);
	    addr = (struct sockaddr *)&sa4;
	}
    }
    len = addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    
    if (getnameinfo(addr, len, addr_buf[i], sizeof(addr_buf[i]),
                    NULL, 0, NI_NUMERICHOST)) {
        debug(DBG_WARN, "getnameinfo failed");
        return "getnameinfo_failed";
    }
    return addr_buf[i];
}

int connectport(int type, char *host, char *port) {
    struct addrinfo hints, *res0, *res;
    int s = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = type;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host, port, &hints, &res0) != 0) {
	debug(DBG_ERR, "connectport: can't resolve host %s port %s", host, port);
	return -1;
    }

    for (res = res0; res; res = res->ai_next) {
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0) {
	    debug(DBG_WARN, "connectport: socket failed");
	    continue;
	}
	if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
	    break;
	debug(DBG_WARN, "connectport: connect failed");
	close(s);
	s = -1;
    }
    freeaddrinfo(res0);
    return s;
}
