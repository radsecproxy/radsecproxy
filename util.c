/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2016, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include "util.h"
#include "debug.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/**
 * @brief verify if str is properly utf-8 encoded
 * 
 * @param str string to verify
 * @param str_len length of the string without terminating null.
 * @return int 1 if valid utf-8, 0 otherwise
 */
int verifyutf8(const unsigned char *str, size_t str_len) {
    const unsigned char *byte;
    size_t charlen;

    for (byte = str; byte < str + str_len; byte++) {
        if (*byte == 0x00)
            return 0;
        if ((*byte & 0x80) == 0x00) {
            if (*byte < 0x20 || *byte == 0x7F)
                return 0;
            continue;
        }
        if (*byte > 0xF4)
            return 0;
        if ((*byte & 0xE0) == 0xC0) {
            if ((*byte & 0xFE) == 0xC0)
                return 0;
            charlen = 2;
        } else if ((*byte & 0xF0) == 0xE0)
            charlen = 3;
        else if ((*byte & 0xF8) == 0xF0)
            charlen = 4;
        else
            return 0;

        if (byte + charlen - 1 >= str + str_len)
            return 0;
        if (charlen == 2 && *byte == 0xC2 && *(byte + 1) < 0xA0)
            return 0;
        if (charlen == 3) {
            if (*byte == 0xE0 && (*(byte + 1) & 0xE0) == 0x80)
                return 0;
            if (*byte == 0xED && (*(byte + 1) & 0xE0) == 0xA0)
                return 0;
        }
        if (charlen == 4) {
            if (*byte == 0xF0 && (*(byte + 1) & 0xF0) == 0x80)
                return 0;
            if (*byte == 0xF4 && (*(byte + 1) & 0xF0) != 0x80)
                return 0;
        }

        while (--charlen)
            if ((*(++byte) & 0xC0) != 0x80)
                return 0;
    }
    return 1;
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
    if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, &optval, optlen) < 0) {
        debug(DBG_ERR, "enable_keepalive: setsockopt TCP_KEEPCNT failed");
    }
    optval = 10;
    if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        debug(DBG_ERR, "enable_keepalive: setsockopt TCP_KEEPIDLE %d failed", optval);
    }
    optval = 10;
    if (setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, &optval, optlen) < 0) {
        debug(DBG_ERR, "enable_keepalive: setsockopt TCP_KEEPINTVL failed");
    }
#endif
    optval = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
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
            debugerrno(errno, DBG_WARN, "bindtoaddr: socket creation failed");
            continue;
        }

        disable_DF_bit(s, res);

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
        if (!getsockopt(s, SOL_SOCKET, SO_ERROR, (void *)&sockerr, &errlen))
            debug(DBG_WARN, "Connection failed: %s", strerror(sockerr));
        else
            debug(DBG_WARN, "Connection failed: unknown error");
    } else if (fds[0].revents & POLLHUP) {
        debug(DBG_WARN, "Connect error: hang up");
    } else if (fds[0].revents & POLLNVAL) {
        debug(DBG_WARN, "Connect error: fd not open");
    } else if (fds[0].revents & POLLOUT) {
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

void accepttcp(int socket, void handler(int)) {
    int s;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    char tmp[INET6_ADDRSTRLEN];

    if (getsockname(socket, (struct sockaddr *)&from, &fromlen) != 0)
        debugerrno(errno, DBG_ERR, "accepttcp: getsockname failed");
    if (listen(socket, 128) != 0) {
        debugerrno(errno, DBG_ERR, "accepttcp: listen on %s failed", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));
        goto exit;
    }
    debug(DBG_DBG, "accepttcp: listening on %s", addr2string((struct sockaddr *)&from, tmp, sizeof(tmp)));

    for (;;) {
        s = accept(socket, (struct sockaddr *)&from, &fromlen);
        if (s < 0) {
            switch (errno) {
            case EBADF:
            case EFAULT:
            case EINVAL:
            case ENOTSOCK:
            case EOPNOTSUPP:
            case EPERM:
                /*non-recoverable errors, exit*/
                debugerrno(errno, DBG_WARN, "accepttcp: accept failed, exiting");
                goto exit;
            case ECONNABORTED:
                break;
            default:
                debugerrno(errno, DBG_WARN, "accepttcp: accept failed, trying again later");
                sleep(1);
            }
            continue;
        }
        handler(s);
    }
exit:
    close(socket);
}

uint32_t connect_wait(struct timeval attempt_start, struct timeval last_success, int firsttry) {
    struct timeval now;

    gettimeofday(&now, NULL);

    if (attempt_start.tv_sec < last_success.tv_sec ||
        attempt_start.tv_sec > now.tv_sec) {
        debug(DBG_WARN, "connect_wait: invalid timers detected!");
        return 60;
    }

    if (now.tv_sec - last_success.tv_sec < 30)
        return 30 - (attempt_start.tv_sec - last_success.tv_sec);

    if (firsttry)
        return 0;

    if (now.tv_sec - attempt_start.tv_sec < 2)
        return 2;

    if (now.tv_sec - attempt_start.tv_sec > 60)
        return 60;

    return now.tv_sec - attempt_start.tv_sec;
}

/**
 * @brief Skip (discard) dgram frame at front of queue
 * 
 * @param socket the dgram socket
 */
void sock_dgram_skip(int socket) {
    uint8_t dummy;

    if (recv(socket, &dummy, sizeof(dummy), MSG_DONTWAIT) == -1)
        debug(DBG_ERR, "sock_dgram_skip: recv failed - %s", strerror(errno));
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
