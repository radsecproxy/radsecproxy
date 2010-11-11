/*
 * Copyright (C) 2006-2009 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "hostport_types.h"

struct hostportres *newhostport(char *hostport, char *default_port, uint8_t prefixok);
int addhostport(struct list **hostports, char **hostport, char *portdefault, uint8_t prefixok);
void freehostport(struct hostportres *hp);
void freehostports(struct list *hostports);
int resolvehostport(struct hostportres *hp, int socktype, uint8_t passive);
int resolvehostports(struct list *hostports, int socktype);
struct addrinfo *resolvepassiveaddrinfo(char *hostport, char *default_port, int socktype);
int addressmatches(struct list *hostports, struct sockaddr *addr, uint8_t checkport);
int connecttcphostlist(struct list *hostports,  struct addrinfo *src);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
