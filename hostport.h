/* Copyright (c) 2009, UNINETT AS
 * Copyright (c) 2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#ifndef _HOSTPORT_H
#define _HOSTPORT_H

struct hostportres {
    char *host;
    char *port;
    uint8_t prefixlen;
    struct addrinfo *addrinfo;
};

struct hostportres *newhostport(char *hostport, char *default_port, uint8_t prefixok);
int addhostport(struct list **hostports, char **hostport, char *portdefault, uint8_t prefixok);
void freehostport(struct hostportres *hp);
void freehostports(struct list *hostports);
int resolvehostport(struct hostportres *hp, int af, int socktype, uint8_t passive);
int resolvehostports(struct list *hostports, int af, int socktype);
struct addrinfo *resolvepassiveaddrinfo(char **hostport, int af, char *default_port, int socktype);
int hostportmatches(struct list *hostports, struct list *matchhostports, uint8_t checkport);
int addressmatches(struct list *hostports, struct sockaddr *addr, uint8_t checkport, struct hostportres **hp);
int connecttcphostlist(struct list *hostports,  struct addrinfo *src, struct hostportres **hpreturn);

#endif /* _HOSTPORT_H */
/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
