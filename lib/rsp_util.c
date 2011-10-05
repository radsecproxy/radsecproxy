/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

/* Code contributions from:
 *
 * Stefan Winter <stefan.winter@restena.lu>
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <stdarg.h>
#include "rsp_debug.h"
#include "rsp_util.h"

char *stringcopy(const char *s, int len) {
    char *r;
    if (!s)
	return NULL;
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

void port_set(struct sockaddr *sa, uint16_t port) {
    switch (sa->sa_family) {
    case AF_INET:
	((struct sockaddr_in *)sa)->sin_port = htons(port);
	break;
    case AF_INET6:
	((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
	break;
    }
}

struct sockaddr *addr_copy(struct sockaddr *in) {
    struct sockaddr *out = NULL;

    switch (in->sa_family) {
    case AF_INET:
	out = malloc(sizeof(struct sockaddr_in));
	if (out) {
	    memset(out, 0, sizeof(struct sockaddr_in));
	    ((struct sockaddr_in *)out)->sin_addr = ((struct sockaddr_in *)in)->sin_addr;
	}
	break;
    case AF_INET6:
	out = malloc(sizeof(struct sockaddr_in6));
	if (out) {
	    memset(out, 0, sizeof(struct sockaddr_in6));
	    ((struct sockaddr_in6 *)out)->sin6_addr = ((struct sockaddr_in6 *)in)->sin6_addr;
	}
	break;
    }
    out->sa_family = in->sa_family;
#ifdef SIN6_LEN
    out->sa_len = in->sa_len;
#endif
    return out;
}

char *addr2string(struct sockaddr *addr) {
    union {
	struct sockaddr *sa;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
    } u;
    struct sockaddr_in sa4;
    static char addr_buf[2][INET6_ADDRSTRLEN];
    static int i = 0;
    i = !i;
    u.sa = addr;
    if (u.sa->sa_family == AF_INET6) {
	if (IN6_IS_ADDR_V4MAPPED(&u.sa6->sin6_addr)) {
	    memset(&sa4, 0, sizeof(sa4));
	    sa4.sin_family = AF_INET;
	    sa4.sin_port = u.sa6->sin6_port;
	    memcpy(&sa4.sin_addr, &u.sa6->sin6_addr.s6_addr[12], 4);
	    u.sa4 = &sa4;
	}
    }
    if (getnameinfo(u.sa, SOCKADDRP_SIZE(u.sa), addr_buf[i], sizeof(addr_buf[i]),
                    NULL, 0, NI_NUMERICHOST)) {
        debug(DBG_WARN, "getnameinfo failed");
        return "getnameinfo_failed";
    }
    return addr_buf[i];
}

#if 0
/* not in use */
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
#endif

/* Disable the "Don't Fragment" bit for UDP sockets. It is set by default, which may cause an "oversized"
   RADIUS packet to be discarded on first attempt (due to Path MTU discovery).
*/

void disable_DF_bit(int socket, struct addrinfo *res) {
    if ((res->ai_family == AF_INET) && (res->ai_socktype == SOCK_DGRAM)) {
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
        /*
         * Turn off Path MTU discovery on IPv4/UDP sockets, Linux variant.
         */
	int r, action;
        debug(DBG_INFO, "disable_DF_bit: disabling DF bit (Linux variant)");
        action = IP_PMTUDISC_DONT;
        r = setsockopt(socket, IPPROTO_IP, IP_MTU_DISCOVER, &action, sizeof(action));
        if (r == -1)
	    debug(DBG_WARN, "Failed to set IP_MTU_DISCOVER");
#else
	debug(DBG_INFO, "Non-Linux platform, unable to unset DF bit for UDP. You should check with tcpdump whether radsecproxy will send its UDP packets with DF bit set!");
#endif
    }
}

int bindtoaddr(struct addrinfo *addrinfo, int family, int reuse, int v6only) {
    int s, on = 1;
    struct addrinfo *res;

    for (res = addrinfo; res; res = res->ai_next) {
	if (family != AF_UNSPEC && family != res->ai_family)
	    continue;
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0) {
	    debug(DBG_WARN, "bindtoaddr: socket failed");
	    continue;
	}

	disable_DF_bit(s,res);

	if (reuse)
	    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef IPV6_V6ONLY
	if (v6only)
	    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
	if (!bind(s, res->ai_addr, res->ai_addrlen))
	    return s;
	debug(DBG_WARN, "bindtoaddr: bind failed");
	close(s);
    }
    return -1;
}

int connectnonblocking(int s, const struct sockaddr *addr, socklen_t addrlen, struct timeval *timeout) {
    int origflags, error = 0, r = -1;
    fd_set writefds;
    socklen_t len;

    origflags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, origflags | O_NONBLOCK);
    if (!connect(s, addr, addrlen)) {
	r = 0;
	goto exit;
    }
    if (errno != EINPROGRESS)
	goto exit;

    FD_ZERO(&writefds);
    FD_SET(s, &writefds);
    if (select(s + 1, NULL, &writefds, NULL, timeout) < 1)
	goto exit;

    len = sizeof(error);
    if (!getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&error, &len) && !error)
	r = 0;

exit:
    fcntl(s, F_SETFL, origflags);
    return r;
}

int connecttcp(struct addrinfo *addrinfo, struct addrinfo *src, uint16_t timeout) {
    int s;
    struct addrinfo *res;
    struct timeval to;

    s = -1;
    if (timeout) {
	if (addrinfo && addrinfo->ai_next && timeout > 5)
	    timeout = 5;
	to.tv_sec = timeout;
	to.tv_usec = 0;
    }

    for (res = addrinfo; res; res = res->ai_next) {
	s = bindtoaddr(src, res->ai_family, 1, 1);
	if (s < 0) {
	    debug(DBG_WARN, "connecttoserver: socket failed");
	    continue;
	}
	if ((timeout
	     ? connectnonblocking(s, res->ai_addr, res->ai_addrlen, &to)
	     : connect(s, res->ai_addr, res->ai_addrlen)) == 0)
	    break;
	debug(DBG_WARN, "connecttoserver: connect failed");
	close(s);
	s = -1;
    }
    return s;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
