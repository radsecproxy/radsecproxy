/* Copyright (c) 2021, SWITCH */
/* See LICENSE for licensing information. */

#include "dns.h"
#include "debug.h"
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>

/**
 * Read a character string from a dns response
 * Character strings are represented by a length byte followd by the characters. 
 * 
 * @param dest where to write the string. The provided buffer must be at least 256 bytes in size
 * @param rdata the rdata pointer from the dns rr
 * @param offset the offset into rdata where the character string starts
 * @param rdlen the rlden of the rr, to avoid reading beyond the record
 * @return the number of bytes read from rdata, or -1 in case of errors
 */
static uint16_t dnsreadcharstring(char *dest, const u_char *rdata, uint16_t offset, uint16_t rdlen) {
    uint16_t len;

    len = *(rdata + offset++);
    if (offset + len > rdlen) {
        debug(DBG_ERR, "dnsreadcharstring: error parsing char string, length is beyond radata!");
        return -1;
    }
    memcpy(dest, rdata + offset, len);
    *(dest + len) = '\0';
    return len + 1;
}

/**
 * Parse SRV response.
 * returns allocated memroy.
 * 
 * @param msg complete DNS msg structure
 * @param rr specific SRV resource record in msg
 * @return new srv_record from resource record
 */
static void *parsesrvrr(ns_msg msg, ns_rr *rr) {
    struct srv_record *response;
    const u_char *rdata;
    int len;

    if (ns_rr_type(*rr) != ns_t_srv)
        return NULL;

    response = malloc(sizeof(struct srv_record));
    if (!response)
        return NULL;

    rdata = ns_rr_rdata(*rr);

    response->ttl = ns_rr_ttl(*rr);
    response->priority = ns_get16(rdata);
    response->weight = ns_get16(rdata + 2);
    response->port = ns_get16(rdata + 4);
    len = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata + 6, response->host, NS_MAXDNAME);
    if (len == -1) {
        debug(DBG_ERR, "parsesrvrr: error during dname uncompress");
        free(response);
        return NULL;
    }
    if (strcmp(response->host, ".") == 0) {
        /* target not available at this domain, as per RFC2782 */
        free(response);
        return NULL;
    }

    debug(DBG_DBG, "parsesrvrr: parsed: host %s, port %d, priority %d, weight %d", response->host, response->port, response->priority, response->weight);
    return response;
}

/**
 * Parse NAPTR response.
 * returns allocated memroy.
 * 
 * @param msg complete DNS msg structure
 * @param rr specific SRV resource record in msg
 * @return new srv_record from resource record
 */
static void *parsenaptrrr(ns_msg msg, ns_rr *rr) {
    struct naptr_record *response;
    const u_char *rdata;
    uint16_t rdlen, offset = 0;
    int len;
    if (ns_rr_type(*rr) != ns_t_naptr) {
        return NULL;
    }

    response = malloc(sizeof(struct naptr_record));
    if (!response)
        return NULL;

    rdata = ns_rr_rdata(*rr);
    rdlen = ns_rr_rdlen(*rr);

    response->ttl = ns_rr_ttl(*rr);
    response->order = ns_get16(rdata);
    response->preference = ns_get16(rdata + 2);

    offset = 4;
    len = dnsreadcharstring(response->flags, rdata, offset, rdlen);
    if (len == -1)
        goto errexit;
    offset += len;

    len = dnsreadcharstring(response->services, rdata, offset, rdlen);
    if (len == -1)
        goto errexit;
    offset += len;

    len = dnsreadcharstring(response->regexp, rdata, offset, rdlen);
    if (len == -1)
        goto errexit;
    offset += len;

    len = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata + offset, response->replacement, NS_MAXDNAME);
    if (len == -1)
        goto errexit;

    /* sanity check, should be exactly at the end of the rdata */
    if (offset + len != rdlen) {
        debug(DBG_ERR, "parsenaptrrr: sanity check failed! unexpected error while parsing naptr rr");
        goto errexit;
    }

    debug(DBG_DBG, "parsenaptrrr: parsed: service %s, regexp %s, replace %s, flags %s, order %d, preference %d",
          response->services, response->regexp, response->replacement, response->flags, response->order, response->preference);
    return response;

errexit:
    free(response);
    return NULL;
}

/* use a packet buffer of 4k insteady of the default 512 byets defined by NS_PACKETSZ */
#define DNS_PACKETSIZE 4096
/**
 * Internal structure to hold resolver state and buffer
 */
struct query_state {
    struct __res_state rs;
    u_char buf[DNS_PACKETSIZE];
    ns_msg msg;
};

/**
 * Cleanup (close) and free a query state
 * 
 * @param state the query state to close
 */
static void querycleanup(struct query_state *state) {
    if (state) {
#if __RES >= 19991006
        res_nclose(&state->rs);
#endif
        free(state);
    }
}

/**
 * Internal helper to perform a dns query.
 * Implicitly initializes the resolver
 * 
 * @param type the DNS type to query
 * @param name the DNS name to query
 * @return initilized query state, its buffer containing the response, or NULL in case of error
 */
static struct query_state *doquery(int type, const char *name, int timeout) {
    int len;
    char *errstring;
    struct query_state *state = malloc(sizeof(struct query_state));
    if (!state) {
        debug(DBG_ERR, "malloc failed");
        return NULL;
    }
    memset(state, 0, sizeof(struct query_state));

    debug(DBG_DBG, "doquery: starting DNS query of type %d for %s", type, name);

#if __RES >= 19991006
    /* new thread-safe res_n* functions introduced in this version */
    if (res_ninit(&state->rs)) {
        debug(DBG_ERR, "doquery: resolver init failed");
        free(state);
        return NULL;
    }

    state->rs.retrans = timeout;
    state->rs.retry = 1;

    len = res_nquery(&state->rs, name, ns_c_in, type, state->buf, DNS_PACKETSIZE);
    if (len == -1) {
        switch (state->rs.res_h_errno) {
#else
    /* only the old interface is available. We have to trust the system to use a thread-safe implementation */
    res_init();
    _res.retrans = timeout;
    _res.retry = 1;

    len = res_query(name, ns_c_in, type, state->buf, DNS_PACKETSIZE);
    if (len == -1) {
        switch (h_errno) {
#endif
        case HOST_NOT_FOUND:
            errstring = "domain not found";
            break;
        case NO_DATA:
            errstring = "no records";
            break;
        case NO_RECOVERY:
            errstring = "format error or refused";
            break;
        case TRY_AGAIN:
            errstring = "server error";
            break;
        default:
            errstring = "internal error";
        }
        debug(DBG_NOTICE, "doquery: dns query failed: %s", errstring);
        querycleanup(state);
        return NULL;
    }

    if (ns_initparse(state->buf, len, &state->msg) == -1) {
        debug(DBG_ERR, "doquery: dns response parser init failed");
        querycleanup(state);
        return NULL;
    }

    /* we should have a valid resopnse at this point, but check the response code anyway, to be sure */
    if (ns_msg_getflag(state->msg, ns_f_rcode) != ns_r_noerror) {
        debug(DBG_ERR, "doquery: dns query returned error code %d", ns_msg_getflag(state->msg, ns_f_rcode));
        querycleanup(state);
        return NULL;
    }
    /* TODO option to check for DNSSEC AD (authentic data) flag? */

    return state;
}

/**
 * Internal helper to find all records of a given type in a section
 * Each matching record is passed to a parser which should read the record and return an allocated memory
 * containing its result.
 * The sum of matching records is returned as a null terminated array of pointers.
 * 
 * @param state the query state containing the result buffer
 * @param type the type to search for
 * @param section the section to serch in
 * @param parser implementation to turn the raw resrouce record into a usable format. 
 * @return the matching and parseable results
 */
static void **findrecords(struct query_state *state, int type, int section, void *parser(ns_msg, ns_rr *)) {
    void **result;
    void *record;
    ns_rr rr;
    int rr_count, i, numresults = 0;

    debug(DBG_DBG, "findrecords: looking for results of type %d in section %d", type, section);

    rr_count = ns_msg_count(state->msg, ns_s_an);
    debug(DBG_DBG, "findrecords: total %d records in section %d", rr_count, section);
    result = calloc(rr_count + 1, sizeof(void *));
    if (!result) {
        debug(DBG_ERR, "malloc failed");
        return NULL;
    }
    for (i = 0; i < rr_count; i++) {
        if (ns_parserr(&state->msg, ns_s_an, i, &rr)) {
            debug(DBG_ERR, "findrecords: error parsing record %d", i);
            continue;
        }
        if (ns_rr_type(rr) == type) {
            record = parser(state->msg, &rr);
            if (!record) {
                debug(DBG_ERR, "findrecords: error parsing record %d", i);
                continue;
            }
            result[numresults++] = record;
        }
    }
    debug(DBG_DBG, "findrecords: %d records of desired type successfully parsed", numresults);
    return result;
}

struct srv_record **querysrv(const char *name, int timeout) {
    struct srv_record **result;
    struct query_state *state;

    state = doquery(ns_t_srv, name, timeout);
    if (!state)
        return NULL;

    result = (struct srv_record **)findrecords(state, ns_t_srv, ns_s_an, &parsesrvrr);
    /* TODO response could include A and AAAA records for the hosts, add this info to the returned result */

    querycleanup(state);
    return result;
}

struct naptr_record **querynaptr(const char *name, int timeout) {
    struct naptr_record **result;
    struct query_state *state;

    state = doquery(ns_t_naptr, name, timeout);
    if (!state)
        return NULL;

    result = (struct naptr_record **)findrecords(state, ns_t_naptr, ns_s_an, &parsenaptrrr);

    querycleanup(state);
    return result;
}

/**
 * Internal generic function to free null terminated lists that contained a response 
 * from calling a query_* function.
 * 
 * @param list the list to free
 */
void freeresponselist(void **list) {
    int i;

    if (list) {
        for (i = 0; list[i]; i++) {
            free(list[i]);
        }
        free(list);
    }
}

void freesrvresponse(struct srv_record **response) {
    freeresponselist((void **)response);
}

void freenaptrresponse(struct naptr_record **response) {
    freeresponselist((void **)response);
}
