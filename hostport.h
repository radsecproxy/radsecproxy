/*
 * Copyright (C) 2006-2009 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

struct hostportres {
    char *host;
    char *port;
    uint8_t prefixlen;
    struct addrinfo *addrinfo;
};

int addhostport(struct list **hostports, char *hostport, char *portdefault, uint8_t prefixok);
void freehostports(struct list *hostports);
int resolvehostports(struct list *hostports, int socktype);
struct addrinfo *resolvepassiveaddrinfo(char *hostport, char *default_port, int socktype);
int addressmatches(struct list *hostports, struct sockaddr *addr);
int connecttcphostlist(struct list *hostports,  struct addrinfo *src);
