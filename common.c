/*
 * Copyright (C) 2012 NORDUnet A/S
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <sys/socket.h>
/*#include <netinet/in.h>*/
#include <netdb.h>
#include <assert.h>
#include "radsecproxy.h"
#include "debug.h"
#include "hostport.h"
#include "util.h"
#include "common.h"

int
addserverextra(const struct clsrvconf *conf,
               int *socket4,
               int *socket6,
               struct addrinfo *addrinfo)
{
    struct hostportres *hp = NULL;

    assert(conf != NULL);
    assert(socket != NULL);

    if (list_first(conf->hostports) == NULL)
        return 0;
    hp = (struct hostportres *) list_first(conf->hostports)->data;
    if (hp == NULL || hp->addrinfo == NULL)
        return 0;

    switch (hp->addrinfo->ai_family) {
    case AF_INET:
	if (*socket4 < 0) {
            /* FIXME: arg 4 is v6only, wtf? */
	    *socket4 = bindtoaddr(addrinfo, AF_INET, 0, 1);
	    if (*socket4 < 0) {
		debug(DBG_ERR,
                      "%s: failed to create client socket for server %s",
                      __func__, conf->name);
                return 0;
            }
	}
	conf->servers->sock = *socket4;
	break;
    case AF_INET6:
	if (*socket6 < 0) {
	    *socket6 = bindtoaddr(addrinfo, AF_INET6, 0, 1);
	    if (*socket6 < 0) {
		debug(DBG_ERR,
                      "%s: failed to create client socket for server %s",
                      __func__, conf->name);
                return 0;
            }
	}
	conf->servers->sock = *socket6;
	break;
    default:
	debug(DBG_ERR, "%s: unsupported address family", __func__);
        return 0;
    }

    return 1;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
