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

void resolve_freehostport(struct hostportres *hp);
struct hostportres *resolve_newhostport(char *hostport, char *default_port, uint8_t prefixok);
int resolve_resolve(struct hostportres *hp, int socktype, uint8_t passive);
