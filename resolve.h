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
