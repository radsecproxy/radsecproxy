/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2016, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <assert.h>
#include "debug.h"
#include "util.h"

char *stringcopy(const char *s, int len) {
    char *r;
    if (!s)
	return NULL;
    if (!len)
	len = strlen(s);
    r = malloc(len + 1);
    if (!r)
	debugx(1, DBG_ERR, "stringcopy: malloc failed");
    memcpy(r, s, len);
    r[len] = '\0';
    return r;
}

void printfchars(char *prefixfmt, char *prefix, char *charfmt, uint8_t *chars, int len) {
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
        if (out == NULL)
            return NULL;
        *(struct sockaddr_in *)out = *(struct sockaddr_in *)in;
	break;
    case AF_INET6:
	out = malloc(sizeof(struct sockaddr_in6));
        if (out == NULL)
            return NULL;
        *(struct sockaddr_in6 *)out = *(struct sockaddr_in6 *)in;
	break;
    }
    assert(out);
#ifdef SIN6_LEN
    out->sa_len = in->sa_len;
#endif
    return out;
}

const char *addr2string(struct sockaddr *addr, char *buf, size_t len) {
    struct sockaddr_in6 *sa6;
    struct sockaddr_in sa4;

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
    if (getnameinfo(addr, SOCKADDRP_SIZE(addr), buf, len,
                    NULL, 0, NI_NUMERICHOST)) {
        debug(DBG_WARN, "getnameinfo failed");
        return "getnameinfo_failed";
    }
    return buf;
}

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

void enable_keepalive(int socket) {
    int optval;
    socklen_t optlen = sizeof(optval);

#if !defined(TCP_KEEPCNT) || !defined(TCP_KEEPIDLE) || !defined(TCP_KEEPINTVL)
    debug(DBG_NOTICE, "TCP Keepalive feature might be limited on this platform");
#else
    optval = 3;
    if(setsockopt(socket, SOL_TCP, TCP_KEEPCNT, &optval, optlen) < 0) {
        debug(DBG_ERR, "enable_keepalive: setsockopt TCP_KEEPCNT failed");
    }
    optval = 10;
    if(setsockopt(socket, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        debug(DBG_ERR, "enable_keepalive: setsockopt TCP_KEEPIDLE %d failed", optval);
    }
    optval = 10;
    if(setsockopt(socket, SOL_TCP, TCP_KEEPINTVL, &optval, optlen) < 0) {
        debug(DBG_ERR, "enable_keepalive: setsockopt TCP_KEEPINTVL failed");
    }
#endif
    optval = 1;
    if(setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        debug(DBG_ERR, "enable_keepalive: setsockopt SO_KEEPALIVE failed");
    }
}

int bindtoaddr(struct addrinfo *addrinfo, int family, int reuse) {
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
	    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
                debugerrno(errno, DBG_WARN, "Failed to set SO_REUSEADDR");
#ifdef IPV6_V6ONLY
	if (family == AF_INET6)
	    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1)
                debugerrno(errno, DBG_WARN, "Failed to set IPV6_V6ONLY");
#endif
	if (!bind(s, res->ai_addr, res->ai_addrlen))
	    return s;
	debug(DBG_WARN, "bindtoaddr: bind failed");
	close(s);
    }
    return -1;
}

int connectnonblocking(int s, const struct sockaddr *addr, socklen_t addrlen, int timeout) {
    int origflags, r = -1, sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    struct pollfd fds[1];

    origflags = fcntl(s, F_GETFL, 0);
    if (origflags == -1) {
        debugerrno(errno, DBG_WARN, "Failed to get flags");
        return -1;
    }
    if (fcntl(s, F_SETFL, origflags | O_NONBLOCK) == -1) {
        debugerrno(errno, DBG_WARN, "Failed to set O_NONBLOCK");
        return -1;
    }
    if (!connect(s, addr, addrlen)) {
	r = 0;
	goto exit;
    }
    if (errno != EINPROGRESS)
	goto exit;

    fds[0].fd = s;
    fds[0].events = POLLOUT;
    if (poll(fds, 1, timeout * 1000) < 1)
	goto exit;

    if (fds[0].revents & POLLERR) {
        if(!getsockopt(s, SOL_SOCKET, SO_ERROR, (void *)&sockerr, &errlen))
            debug(DBG_WARN, "Connection failed: %s", strerror(sockerr));
        else
            debug(DBG_WARN, "Connection failed: unknown error");
    } else if (fds[0].revents & POLLHUP) {
            debug(DBG_WARN, "Connect error: hang up");
    } else if (fds[0].revents & POLLNVAL) {
            debug(DBG_WARN, "Connect error: fd not open");
    } else if(fds[0].revents & POLLOUT) {
        debug(DBG_DBG, "Connection up");
        r = 0;
    }

exit:
    if (fcntl(s, F_SETFL, origflags) == -1)
        debugerrno(errno, DBG_WARN, "Failed to set original flags back");
    return r;
}

int connecttcp(struct addrinfo *addrinfo, struct addrinfo *src, uint16_t timeout) {
    int s;
    struct addrinfo *res;

    s = -1;
    if (timeout) {
	if (addrinfo && addrinfo->ai_next && timeout > 5)
	    timeout = 5;
    }

    for (res = addrinfo; res; res = res->ai_next) {
	s = bindtoaddr(src, res->ai_family, 1);
	if (s < 0) {
	    debug(DBG_WARN, "connecttoserver: socket failed");
	    continue;
	}
	if ((timeout
	     ? connectnonblocking(s, res->ai_addr, res->ai_addrlen, timeout)
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
