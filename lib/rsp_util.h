/* Copyright (c) 2007-2009, UNINETT AS */
/* See LICENSE for licensing information. */

#include <sys/socket.h>
#include <netdb.h>

#define SOCKADDR_SIZE(addr) ((addr).ss_family == AF_INET ?	\
			     sizeof(struct sockaddr_in) :	\
			     sizeof(struct sockaddr_in6))

#define SOCKADDRP_SIZE(addr) ((addr)->sa_family == AF_INET ?	\
			      sizeof(struct sockaddr_in) :	\
			      sizeof(struct sockaddr_in6))

#if defined (__cplusplus)
extern "C" {
#endif

char *stringcopy(const char *s, int len);
char *addr2string(struct sockaddr *addr);
struct sockaddr *addr_copy(struct sockaddr *in);
void port_set(struct sockaddr *sa, uint16_t port);

void printfchars(char *prefixfmt, char *prefix, char *charfmt, char *chars, int len);
void disable_DF_bit(int socket, struct addrinfo *res);
int bindtoaddr(struct addrinfo *addrinfo, int family, int reuse, int v6only);
int connecttcp(struct addrinfo *addrinfo, struct addrinfo *src, uint16_t timeout);

#if defined (__cplusplus)
}
#endif

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
