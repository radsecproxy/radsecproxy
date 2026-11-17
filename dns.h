/* Copyright (c) 2021, SWITCH */
/* See LICENSE for licensing information. */

#ifndef _DNS_H
#define _DNS_H

#include <sys/types.h>
#include <arpa/nameser.h>
#include <stdlib.h>

/* maximum character string length in a DNS response, including null-terminator */
#define MAXCHARSTRLEN 256

struct naptr_record {
    uint32_t ttl;
    uint16_t order;
    uint16_t preference;
    char flags[MAXCHARSTRLEN];
    char services[MAXCHARSTRLEN];
    char regexp[MAXCHARSTRLEN];
    char replacement[NS_MAXDNAME];
};

struct srv_record {
    uint32_t ttl;
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char host[NS_MAXDNAME];
    /* TODO add A and AAAA records from additional section */
};

/**
 * query DNS NAPTR record for name
 * caller must free memory by calling freenaptrresponse
 * 
 * @param name the name to query
 * @param timeout query timeout
 * @return null terminated array of struct naptr_record*
 */
struct naptr_record **querynaptr(const char *name, int timeout);

/**
 * free memory allocated by querynaptr
 * 
 * @param response the response to free
 */
void freenaptrresponse(struct naptr_record **response);

/** 
 * query a DNS SRV record for name.
 * caller must free memory by calling freesrvresponse.
 * 
 * @param name the name to query
 * @param timeout query timeout
 * @return null terminated array of struct srv_record*
 */
struct srv_record **querysrv(const char *name, int timeout);

/**
 * free memory allocated by querysrv
 * 
 * @param response the response to free
 */
void freesrvresponse(struct srv_record **response);

/**
 * select the NAPTR records usable for dynamic discovery of a service and put
 * them in the order they are to be tried: records whose service field matches
 * (case-insensitive) and whose flag is "S", sorted by order, then preference,
 * ascending (the sort key of RFC 3403 section 4.1); records with equal order
 * and preference keep their response order. RFC 7585 evaluates the discovered
 * targets in this order ("greedy result evaluation", defined in section 3.3,
 * applied in the algorithm of section 3.4.3) and tries the next one in the set
 * when a connection fails (section 2.1.1.2).
 *
 * @param naptr null terminated array as returned by querynaptr
 * @param service the service to look for, e.g. "aaa+auth:radius.tls.tcp"
 * @return newly allocated null terminated array of pointers into naptr (not
 *         copies, do not free the elements), or NULL on allocation failure.
 *         caller must free the array itself.
 */
struct naptr_record **naptrselect(struct naptr_record **naptr, const char *service);

/**
 * DNS name to use for dynamic discovery of a 3GPP realm.
 *
 * 3GPP TS 23.003 realms (wlan.mnc<MNC>.mcc<MCC>.3gppnetwork.org) are only
 * resolvable on the inter-PLMN backbone; the publicly resolvable records live
 * under the pub.3gppnetwork.org sub-domain (GSMA IR.67). OpenRoaming requires a
 * RadSec client to insert ".pub" into such a realm before dynamic discovery
 * (draft-tomas-openroaming section 6.2). The User-Name is never modified.
 *
 * @param realm the realm as taken from the User-Name
 * @return newly allocated name to query, or NULL if the realm does not end in
 *         mnc<MNC>.mcc<MCC>.3gppnetwork.org (a realm already under
 *         pub.3gppnetwork.org included). caller must free the result.
 *         exits on allocation failure, like stringcopy.
 */
char *dns3gpppublicname(const char *realm);

#endif /*_DNS_H*/
