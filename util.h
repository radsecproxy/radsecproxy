/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2016-2017, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>

#define SOCKADDR_SIZE(addr) ((addr).ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define SOCKADDRP_SIZE(addr) ((addr)->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

char *stringcopy(const char *s, int len);
int verifyutf8(const unsigned char *str, size_t str_len);
const char *addr2string(struct sockaddr *addr, char *buf, size_t len);
struct sockaddr *addr_copy(struct sockaddr *in);
void port_set(struct sockaddr *sa, uint16_t port);
void sock_dgram_skip(int socket);

void printfchars(char *prefixfmt, char *prefix, char *charfmt, uint8_t *chars, int len);
void disable_DF_bit(int socket, struct addrinfo *res);
void enable_keepalive(int socket);
int bindtoaddr(struct addrinfo *addrinfo, int family, int reuse);
int connecttcp(struct addrinfo *addrinfo, struct addrinfo *src, uint16_t timeout);
void accepttcp(int socket, void handler(int));
uint32_t connect_wait(struct timeval attempt_start, struct timeval last_success, int firsttry);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
