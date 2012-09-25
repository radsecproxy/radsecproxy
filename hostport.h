/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

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
struct addrinfo *resolvepassiveaddrinfo(char *hostport, int af, char *default_port, int socktype);
int addressmatches(struct list *hostports, struct sockaddr *addr, uint8_t checkport);
int connecttcphostlist(struct list *hostports,  struct addrinfo *src);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
