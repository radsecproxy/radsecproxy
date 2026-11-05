/* Copyright (c) 2026, Nova Labs */
/* Copyright (c) 2026, CyB0rgg */
/* See LICENSE for licensing information. */

#include "reverse_coa.h"

#include "coa.h"
#include "debug.h"
#include "list.h"
#include "radmsg.h"
#include "udp.h"
#include "util.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/* rfc 5176 6.3: the same window for duplicate detection and event-timestamp */
#define REVERSE_COA_DEDUP_WINDOW 300
#define MAX_REVERSE_COA_FAILOVER 8

/* the clients registered for one ReverseCoAOperatorRealm value */
struct reverse_coa_realm {
    char *value;
    regex_t regex;
    struct list *routes;
};

struct reverse_coa_route {
    uint32_t refcount;
    pthread_mutex_t refmutex;
    struct client *target;
};

/* where a request went, kept with the duplicate detection slot for retransmissions */
struct reverse_coa_sent {
    struct reverse_coa_route *route;
    uint8_t id;
};

struct reverse_coa_route *reverse_coa_route_new(struct client *target) {
    struct reverse_coa_route *route = malloc(sizeof(*route));
    if (!route)
        return NULL;
    route->refcount = 1;
    pthread_mutex_init(&route->refmutex, NULL);
    route->target = target;
    return route;
}

static void reverse_coa_route_ref(struct reverse_coa_route *route) {
    if (!route)
        return;
    pthread_mutex_lock(&route->refmutex);
    route->refcount++;
    pthread_mutex_unlock(&route->refmutex);
}

void reverse_coa_route_deref(struct reverse_coa_route *route) {
    uint32_t remaining;

    if (!route)
        return;
    pthread_mutex_lock(&route->refmutex);
    remaining = --route->refcount;
    pthread_mutex_unlock(&route->refmutex);
    if (remaining == 0) {
        pthread_mutex_destroy(&route->refmutex);
        free(route);
    }
}

struct client *_internal_reverse_coa_route_target(struct reverse_coa_route *route) { return route->target; }

static struct list *reverse_coa_realm_list;
static struct list *reverse_coa_nas_routes;
static pthread_mutex_t realm_reverse_coa_lock = PTHREAD_MUTEX_INITIALIZER;

void init_reverse_coa(void) {
    reverse_coa_realm_list = list_create();
    reverse_coa_nas_routes = list_create();
    if (!reverse_coa_realm_list || !reverse_coa_nas_routes)
        debugx(1, DBG_ERR, "malloc failed");
}

/* the token naming a client connection in Operator-NAS-Identifier, see addclient() */
int reverse_coa_newtoken(char *token) {
    uint8_t r[REVERSE_COA_TOKEN_LEN / 2];
    int i;

    if (!RAND_bytes(r, sizeof(r)))
        return 0;
    for (i = 0; i < (int)sizeof(r); i++)
        sprintf(token + 2 * i, "%02x", r[i]);
    return 1;
}

/* ReverseCoATokenKey: with it, a client's token is derived from its identity, so it is
   the same after a restart and on every proxy sharing the key (rfc 8559 3.4 obfuscates
   the nas address under a local key the same way) */
static char *reverse_coa_token_key = NULL;

void reverse_coa_settokenkey(const char *key) {
    free(reverse_coa_token_key);
    reverse_coa_token_key = key ? strdup(key) : NULL;
}

/* the first 8 bytes of HMAC-SHA256 over the identity and a qualifier under the key, as
   hex; random when there is no key or no identity */
static int keyedtoken(char *token, const char *identity, const char *qualifier) {
    uint8_t md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    char input[1024];
    int i, n;

    if (!reverse_coa_token_key || !identity || !*identity)
        return reverse_coa_newtoken(token);
    n = snprintf(input, sizeof(input), "%s\n%s", identity, qualifier ? qualifier : "");
    if (n < 0 || n >= (int)sizeof(input))
        return 0;
    if (!HMAC(EVP_sha256(), reverse_coa_token_key, strlen(reverse_coa_token_key), (const uint8_t *)input, n, md, &mdlen) ||
        mdlen < REVERSE_COA_TOKEN_LEN / 2)
        return 0;
    for (i = 0; i < REVERSE_COA_TOKEN_LEN / 2; i++)
        sprintf(token + 2 * i, "%02x", md[i]);
    return 1;
}

/* the token of a connection that has not sent a request yet: its identity (certificate
   subject, psk identity, or the block name) and the address it comes from */
int reverse_coa_peertoken(char *token, const char *identity, const struct sockaddr *addr) {
    char addrbuf[INET6_ADDRSTRLEN];

    return keyedtoken(token, identity, addr ? addr2string((struct sockaddr *)addr, addrbuf, sizeof(addrbuf)) : "");
}

/* the token naming the nas that sent msg: its identity and what it says it is, the
   NAS-Identifier it sends, or its NAS-IP-Address or NAS-IPv6-Address when it sends no
   NAS-Identifier (rfc 2865 4.1 requires one of them), or the address the request came
   from when it sends neither. the same nas gets the same value on every connection,
   from every address and on every proxy with the key, which is what rfc 8559 3.4 asks
   of the value: a token that identifies a nas, obfuscated under a local key. a fleet on
   one certificate gets a token per nas because each nas sends its own NAS-Identifier */
int reverse_coa_nastoken(char *token, const char *identity, struct radmsg *msg, const struct sockaddr *addr) {
    struct tlv *attr = radmsg_gettype(msg, RAD_Attr_NAS_Identifier);
    struct sockaddr_storage nasaddr;
    char qualifier[256];

    if (attr && attr->l) {
        memcpy(qualifier, attr->v, attr->l);
        qualifier[attr->l] = '\0';
    } else if (reverse_coa_nas_addr(msg, &nasaddr))
        addr2string((struct sockaddr *)&nasaddr, qualifier, sizeof(qualifier));
    else
        return reverse_coa_peertoken(token, identity, addr);
    return keyedtoken(token, identity, qualifier);
}

/* a value in slashes is a regexp, anything else is matched literally, as in addrealm() */
static int reverse_coa_realm_regcomp(const char *value, regex_t *re) {
    char *regex, *s;
    int n, rc;

    regex = malloc(2 * strlen(value) + 3);
    if (!regex)
        return 0;
    if (*value == '/') {
        strcpy(regex, value + 1);
        if (*regex && regex[strlen(regex) - 1] == '/')
            regex[strlen(regex) - 1] = '\0';
    } else {
        regex[0] = '^';
        for (n = 1, s = (char *)value; *s; s++) {
            if (*s == '.')
                regex[n++] = '\\';
            regex[n++] = *s;
        }
        regex[n++] = '$';
        regex[n] = '\0';
    }
    rc = regcomp(re, regex, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    free(regex);
    return !rc;
}

static struct reverse_coa_realm *reverse_coa_realm_new(const char *value) {
    struct reverse_coa_realm *r = malloc(sizeof(struct reverse_coa_realm));

    if (!r) {
        debug(DBG_ERR, "reverse_coa_realm_new: malloc failed");
        return NULL;
    }
    r->value = stringcopy(value, 0);
    r->routes = list_create();
    if (r->value && r->routes && reverse_coa_realm_regcomp(value, &r->regex))
        return r;
    debug(DBG_ERR, "reverse_coa_realm_new: failed to add ReverseCoAOperatorRealm %s", value);
    free(r->value);
    list_destroy(r->routes);
    free(r);
    return NULL;
}

/* compiles the block's ReverseCoAOperatorRealm values once, at configuration time */
int reverse_coa_compile_realms(struct clsrvconf *conf) {
    int i, n;

    for (n = 0; conf->reverse_coa_realms && conf->reverse_coa_realms[n]; n++)
        ;
    if (!n)
        return 1;
    conf->reverse_coa_regexes = calloc(n, sizeof(regex_t));
    if (!conf->reverse_coa_regexes)
        return 0;
    for (i = 0; i < n; i++)
        if (!reverse_coa_realm_regcomp(conf->reverse_coa_realms[i], &conf->reverse_coa_regexes[i])) {
            debug(DBG_ERR, "reverse_coa_compile_realms: invalid ReverseCoAOperatorRealm %s", conf->reverse_coa_realms[i]);
            while (i--)
                regfree(&conf->reverse_coa_regexes[i]);
            free(conf->reverse_coa_regexes);
            conf->reverse_coa_regexes = NULL;
            return 0;
        }
    return 1;
}

void reverse_coa_free_realms(struct clsrvconf *conf) {
    int i;

    if (!conf->reverse_coa_regexes)
        return;
    for (i = 0; conf->reverse_coa_realms && conf->reverse_coa_realms[i]; i++)
        regfree(&conf->reverse_coa_regexes[i]);
    free(conf->reverse_coa_regexes);
    conf->reverse_coa_regexes = NULL;
}

/* NASidentifier in slashes is a regexp: the block is a fleet of nases, each connection
   told apart by the NAS-Identifier and address it sends (learn_nas_identity()). a
   literal value names a single nas, as before */
int reverse_coa_compile_nas_identifier(struct clsrvconf *conf) {
    if (!conf->nas_identifier || conf->nas_identifier[0] != '/')
        return 1;
    conf->nas_identifier_regex = malloc(sizeof(regex_t));
    if (!conf->nas_identifier_regex)
        return 0;
    if (reverse_coa_realm_regcomp(conf->nas_identifier, conf->nas_identifier_regex))
        return 1;
    free(conf->nas_identifier_regex);
    conf->nas_identifier_regex = NULL;
    return 0;
}

void reverse_coa_free_nas_identifier(struct clsrvconf *conf) {
    if (!conf->nas_identifier_regex)
        return;
    regfree(conf->nas_identifier_regex);
    free(conf->nas_identifier_regex);
    conf->nas_identifier_regex = NULL;
}

/* returns 1 if one of the block's ReverseCoAOperatorRealm values matches realm */
static int conf_realm_matches(struct clsrvconf *conf, const char *realm) {
    int i;

    for (i = 0; conf->reverse_coa_regexes && conf->reverse_coa_realms[i]; i++)
        if (!regexec(&conf->reverse_coa_regexes[i], realm, 0, NULL, 0))
            return 1;
    return 0;
}

static void reverse_coa_realm_free(struct reverse_coa_realm *r) {
    regfree(&r->regex);
    free(r->value);
    list_destroy(r->routes);
    free(r);
}

/* realm_reverse_coa_lock held */
static struct reverse_coa_realm *reverse_coa_realm_find(const char *value) {
    struct list_node *node;
    struct reverse_coa_realm *r;

    for (node = list_first(reverse_coa_realm_list); node; node = list_next(node)) {
        r = (struct reverse_coa_realm *)node->data;
        if (!strcmp(r->value, value))
            return r;
    }
    return NULL;
}

void register_reverse_coa_client(struct client *client) {
    struct reverse_coa_route *route;
    struct reverse_coa_realm *r;
    int i;

    if (!client || !client->conf || !client->reverse_coa_route)
        return;
    route = client->reverse_coa_route;

    pthread_mutex_lock(&realm_reverse_coa_lock);
    reverse_coa_route_ref(route);
    if (!list_push(reverse_coa_nas_routes, route)) {
        reverse_coa_route_deref(route);
        debug(DBG_ERR, "register_reverse_coa_client: malloc failed");
    }
    for (i = 0; client->conf->reverse_coa_realms && client->conf->reverse_coa_realms[i]; i++) {
        r = reverse_coa_realm_find(client->conf->reverse_coa_realms[i]);
        if (!r) {
            r = reverse_coa_realm_new(client->conf->reverse_coa_realms[i]);
            if (!r)
                continue;
            if (!list_push(reverse_coa_realm_list, r)) {
                debug(DBG_ERR, "register_reverse_coa_client: malloc failed");
                reverse_coa_realm_free(r);
                continue;
            }
        }
        reverse_coa_route_ref(route);
        if (!list_push(r->routes, route)) {
            reverse_coa_route_deref(route);
            debug(DBG_ERR, "register_reverse_coa_client: malloc failed");
        } else
            debug(DBG_DBG, "register_reverse_coa_client: client %s registered for realm %s", client->conf->name, r->value);
    }
    pthread_mutex_unlock(&realm_reverse_coa_lock);
}

/* realm_reverse_coa_lock held; returns the number of references dropped */
static int reverse_coa_route_remove(struct list *routes, struct reverse_coa_route *route) {
    int n = 0;

    while (list_count(routes) > 0) {
        uint32_t before = list_count(routes);
        list_removedata(routes, route);
        if (list_count(routes) == before)
            break;
        reverse_coa_route_deref(route);
        n++;
    }
    return n;
}

void unregister_reverse_coa_client(struct client *client) {
    struct reverse_coa_route *route;
    struct reverse_coa_realm *r;
    int i;

    if (!client || !client->conf || !client->reverse_coa_route)
        return;
    route = client->reverse_coa_route;

    pthread_mutex_lock(&realm_reverse_coa_lock);
    reverse_coa_route_remove(reverse_coa_nas_routes, route);
    for (i = 0; client->conf->reverse_coa_realms && client->conf->reverse_coa_realms[i]; i++) {
        r = reverse_coa_realm_find(client->conf->reverse_coa_realms[i]);
        if (!r)
            continue;
        if (reverse_coa_route_remove(r->routes, route))
            debug(DBG_DBG, "unregister_reverse_coa_client: client %s unregistered from realm %s", client->conf->name, r->value);
        if (list_count(r->routes) == 0) {
            list_removedata(reverse_coa_realm_list, r);
            reverse_coa_realm_free(r);
        }
    }
    pthread_mutex_unlock(&realm_reverse_coa_lock);

    /* waits for a send in progress to the client, see send_coa_to_client() */
    pthread_mutex_lock(&route->refmutex);
    route->target = NULL;
    pthread_mutex_unlock(&route->refmutex);
}

static void expire_reverse_coa_rqs(struct client *client);

/* client->lock held */
static void clear_rqout(struct client *client, struct rqout *rqout) {
    if (rqout->rq) {
        freerq(rqout->rq);
        client->reverse_coa_pending--;
    }
    rqout->rq = NULL;
    memset(&rqout->expiry, 0, sizeof(struct timeval));
}

/* a udp client entry with a reverse coa in flight must outlive the expiry sweep */
int client_has_pending_reverse_coa(struct client *client) {
    int pending;

    if (!client || !client->reverse_coa_rqs)
        return 0;
    pthread_mutex_lock(&client->lock);
    expire_reverse_coa_rqs(client);
    pending = client->reverse_coa_pending > 0;
    pthread_mutex_unlock(&client->lock);
    return pending;
}

void free_reverse_coa_rqs(struct client *client) {
    int i;

    if (!client->reverse_coa_rqs)
        return;
    for (i = 0; i < MAX_REQUESTS; i++)
        clear_rqout(client, &client->reverse_coa_rqs[i]);
    free(client->reverse_coa_rqs);
    client->reverse_coa_rqs = NULL;
}

/* server->reverse_coa_lock held */
static void clear_dedup_slot(struct coa_dedup_slot *slot) {
    free(slot->replybuf);
    reverse_coa_route_deref(slot->route);
    memset(slot, 0, sizeof(*slot));
}

static int slot_expired(const struct coa_dedup_slot *slot, time_t now) {
    return now >= slot->received + REVERSE_COA_DEDUP_WINDOW;
}

/* a retransmission of a request still in flight to a udp or dtls client is sent
   again, rfc 5176 2.3; on a tls or tcp connection the transport does that */
static void resend_reverse_coa(struct server *server, struct reverse_coa_route *route, uint8_t id, struct radmsg *msg) {
    struct client *client;
    struct rqout *rqout;
    struct request *rq = NULL;

    pthread_mutex_lock(&route->refmutex);
    client = route->target;
    if (client && (client->conf->type == RAD_UDP || client->conf->type == RAD_DTLS)) {
        pthread_mutex_lock(&client->lock);
        rqout = client->reverse_coa_rqs ? &client->reverse_coa_rqs[id] : NULL;
        if (rqout && rqout->rq && rqout->rq->rqid == msg->id && !memcmp(rqout->rq->rqauth, msg->auth, 16))
            rq = newrqref(rqout->rq);
        pthread_mutex_unlock(&client->lock);
        if (rq) {
            debug(DBG_INFO, "resend_reverse_coa: %s (id %d) from server %s sent again to client %s",
                  radmsgtype2string(msg->code), msg->id, server->conf->name, client->conf->name);
            if (sendreply(rq) < 1)
                debug(DBG_ERR, "resend_reverse_coa: sending to client %s failed", client->conf->name);
        }
    }
    pthread_mutex_unlock(&route->refmutex);
}

static int is_coa_duplicate(struct server *server, struct radmsg *msg) {
    struct coa_dedup_slot *slot;
    struct reverse_coa_route *route = NULL;
    time_t now;
    uint8_t *replybuf = NULL;
    uint8_t id = 0;
    int replybuflen = 0;

    pthread_mutex_lock(&server->reverse_coa_lock);
    slot = &server->reverse_coa_seen[msg->id];
    if (!slot->occupied) {
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return 0;
    }
    time(&now);
    if (slot_expired(slot, now)) {
        clear_dedup_slot(slot);
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return 0;
    }
    if (memcmp(slot->auth, msg->auth, 16) != 0) {
        /* new request reusing the id, not a retransmission */
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return 0;
    }
    if (slot->replybuf && slot->replybuflen > 0) {
        replybuf = malloc(slot->replybuflen);
        if (replybuf) {
            memcpy(replybuf, slot->replybuf, slot->replybuflen);
            replybuflen = slot->replybuflen;
        } else
            debug(DBG_ERR, "is_coa_duplicate: malloc failed");
    } else if (slot->route) {
        route = slot->route;
        id = slot->id;
        reverse_coa_route_ref(route);
    }
    pthread_mutex_unlock(&server->reverse_coa_lock);

    if (replybuf) {
        debug(DBG_INFO, "is_coa_duplicate: resending cached response for id %d to server %s",
              msg->id, server->conf->name);
        server->conf->pdef->clientradput(server, replybuf, replybuflen);
        free(replybuf);
    } else if (route) {
        resend_reverse_coa(server, route, id, msg);
        reverse_coa_route_deref(route);
    } else
        debug(DBG_DBG, "is_coa_duplicate: retransmission of id %d from server %s, response pending",
              msg->id, server->conf->name);
    return 1;
}

int _internal_is_coa_duplicate(struct server *server, struct radmsg *msg) { return is_coa_duplicate(server, msg); }

static void expire_coa_dedup_entries(struct server *server) {
    time_t now;
    int i;

    time(&now);
    pthread_mutex_lock(&server->reverse_coa_lock);
    if (now >= server->last_dedup_cleanup + REVERSE_COA_DEDUP_WINDOW) {
        for (i = 0; i < MAX_REQUESTS; i++)
            if (server->reverse_coa_seen[i].occupied && slot_expired(&server->reverse_coa_seen[i], now))
                clear_dedup_slot(&server->reverse_coa_seen[i]);
        server->last_dedup_cleanup = now;
    }
    pthread_mutex_unlock(&server->reverse_coa_lock);
}

static void record_coa_dedup(struct server *server, uint8_t id, uint8_t *auth) {
    struct coa_dedup_slot *slot;

    pthread_mutex_lock(&server->reverse_coa_lock);
    slot = &server->reverse_coa_seen[id];
    clear_dedup_slot(slot);
    memcpy(slot->auth, auth, 16);
    time(&slot->received);
    slot->occupied = 1;
    pthread_mutex_unlock(&server->reverse_coa_lock);
}

void _internal_record_coa_dedup(struct server *server, uint8_t id, uint8_t *auth) { record_coa_dedup(server, id, auth); }

/* takes over the reference held in sent */
static void record_coa_route(struct server *server, uint8_t id, uint8_t *auth, struct reverse_coa_sent *sent) {
    struct coa_dedup_slot *slot;

    pthread_mutex_lock(&server->reverse_coa_lock);
    slot = &server->reverse_coa_seen[id];
    if (slot->occupied && !memcmp(slot->auth, auth, 16) && !slot->route) {
        slot->route = sent->route;
        slot->id = sent->id;
        sent->route = NULL;
    }
    pthread_mutex_unlock(&server->reverse_coa_lock);
    reverse_coa_route_deref(sent->route);
    sent->route = NULL;
}

static void cache_coa_dedup_reply(struct server *server, uint8_t id, uint8_t *auth,
                                  uint8_t *buf, int buflen) {
    struct coa_dedup_slot *slot;

    pthread_mutex_lock(&server->reverse_coa_lock);
    slot = &server->reverse_coa_seen[id];
    if (!slot->occupied || memcmp(slot->auth, auth, 16) != 0 || slot->replybuf) {
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return;
    }
    slot->replybuf = malloc(buflen);
    if (slot->replybuf) {
        memcpy(slot->replybuf, buf, buflen);
        slot->replybuflen = buflen;
    } else
        debug(DBG_ERR, "cache_coa_dedup_reply: malloc failed");
    pthread_mutex_unlock(&server->reverse_coa_lock);
}

void drain_coa_dedup(struct server *server) {
    int i;

    if (!server->reverse_coa_seen)
        return;
    pthread_mutex_lock(&server->reverse_coa_lock);
    for (i = 0; i < MAX_REQUESTS; i++)
        if (server->reverse_coa_seen[i].occupied)
            clear_dedup_slot(&server->reverse_coa_seen[i]);
    pthread_mutex_unlock(&server->reverse_coa_lock);
}

/* another live connection of the block carrying the same token from another address:
   two nases on one certificate sending the same NAS-Identifier, which a CoA cannot tell
   apart; the one that sent a request most recently would get it */
static void warn_token_shared(struct client *from) {
    struct list_node *node;
    struct client *other;
    char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
    int shared = 0;

    if (from->conf->type == RAD_UDP || !from->conf->lock)
        return;
    pthread_mutex_lock(from->conf->lock);
    for (node = list_first(from->conf->clients); node && !shared; node = list_next(node)) {
        other = (struct client *)node->data;
        if (other == from || !other->addr || !from->addr || addr_equal_ip(other->addr, from->addr))
            continue;
        pthread_mutex_lock(&other->lock);
        shared = !strcmp(other->token, from->token);
        pthread_mutex_unlock(&other->lock);
    }
    pthread_mutex_unlock(from->conf->lock);
    if (shared)
        debug_limit(DBG_WARN, "learn_nas_identity: two connections of client %s from %s and %s name the same nas, a CoA for it goes to the one that spoke last",
                    from->conf->name, addr2string(from->addr, a, sizeof(a)), addr2string(other->addr, b, sizeof(b)));
}

/* notes when the connection last sent a request and the token naming the nas it is,
   see reverse_coa_nastoken(); on a NASidentifier /regexp/ block also what it says it
   is: the NAS-Identifier and the NAS-IP-Address or NAS-IPv6-Address of its own
   requests. a CoA-Request or Disconnect-Request for it carries the same values (rfc
   5176 section 3) */
void learn_nas_identity(struct client *from, struct radmsg *msg) {
    struct tlv *attr;
    struct sockaddr_storage addr;
    char token[REVERSE_COA_TOKEN_LEN + 1];
    int has_addr, changed = 0;

    if (!reverse_coa_nastoken(token, from->identity, msg, from->addr))
        token[0] = '\0';
    pthread_mutex_lock(&from->lock);
    time(&from->last_request);
    if (token[0] && strcmp(token, from->token)) {
        memcpy(from->token, token, sizeof(from->token));
        changed = 1;
    }
    pthread_mutex_unlock(&from->lock);
    if (changed)
        warn_token_shared(from);
    if (!from->conf->nas_identifier_regex)
        return;
    attr = radmsg_gettype(msg, RAD_Attr_NAS_Identifier);
    if (attr && !attr->l)
        attr = NULL;
    has_addr = reverse_coa_nas_addr(msg, &addr);
    if (!attr && !has_addr)
        return;
    pthread_mutex_lock(&from->lock);
    if (attr) {
        memcpy(from->nas_identifier_seen, attr->v, attr->l);
        from->nas_identifier_seen[attr->l] = '\0';
        from->nas_identifier_seen_len = attr->l;
    }
    if (has_addr) {
        memcpy(&from->nas_addr_seen, &addr, sizeof(addr));
        from->nas_addr_seen_set = 1;
    }
    pthread_mutex_unlock(&from->lock);
}

/* a fleet block: the nas is the connection whose own NAS-Identifier the request carries
   (and the regexp admits); when either side has no NAS-Identifier, the address it sent.
   returns 1 on a match, 0 when undecided (the caller then tries the connection's own
   address), -1 when the request names another nas */
static int match_learned_nas(struct client *client, struct radmsg *msg) {
    struct tlv *attr = radmsg_gettype(msg, RAD_Attr_NAS_Identifier);
    struct sockaddr_storage addr;
    int result = 0;

    pthread_mutex_lock(&client->lock);
    if (attr && attr->l && client->nas_identifier_seen_len)
        result = (attr->l == client->nas_identifier_seen_len && !memcmp(attr->v, client->nas_identifier_seen, attr->l) &&
                  !regexec(client->conf->nas_identifier_regex, client->nas_identifier_seen, 0, NULL, 0))
                     ? 1
                     : -1;
    else if (client->nas_addr_seen_set && reverse_coa_nas_addr(msg, &addr))
        result = addr_equal_ip((struct sockaddr *)&client->nas_addr_seen, (struct sockaddr *)&addr) ? 1 : -1;
    pthread_mutex_unlock(&client->lock);
    return result;
}

/* returns 1 if the request names the client by Operator-NAS-Identifier, NAS-Identifier,
   NAS-IP-Address or NAS-IPv6-Address */
static int match_nas_identifier(struct client *client, struct radmsg *msg) {
    struct tlv *attr;
    const char *id = client->conf->nas_identifier;
    size_t idlen = id ? strlen(id) : 0;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    int learned;

    if (client->conf->nas_identifier_regex) {
        learned = match_learned_nas(client, msg);
        if (learned)
            return learned > 0;
    } else if (id) {
        attr = radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier);
        if (attr && attr->l == idlen + 1 && !memcmp(attr->v + 1, id, idlen))
            return 1;
        attr = radmsg_gettype(msg, RAD_Attr_NAS_Identifier);
        if (attr && attr->l == idlen && !memcmp(attr->v, id, idlen))
            return 1;
    }
    if (!client->addr)
        return 0;
    attr = radmsg_gettype(msg, RAD_Attr_NAS_IP_Address);
    if (attr && attr->l == 4) {
        if (client->addr->sa_family == AF_INET) {
            sin = (struct sockaddr_in *)client->addr;
            if (!memcmp(&sin->sin_addr, attr->v, 4))
                return 1;
        } else if (client->addr->sa_family == AF_INET6) {
            sin6 = (struct sockaddr_in6 *)client->addr;
            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr) && !memcmp(&sin6->sin6_addr.s6_addr[12], attr->v, 4))
                return 1;
        }
    }
    attr = radmsg_gettype(msg, RAD_Attr_NAS_IPv6_Address);
    if (attr && attr->l == 16 && client->addr->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *)client->addr;
        if (!memcmp(&sin6->sin6_addr, attr->v, 16))
            return 1;
    }
    return 0;
}

int _internal_match_nas_identifier(struct client *client, struct radmsg *msg) { return match_nas_identifier(client, msg); }

/* the token from Operator-NAS-Identifier, if the attribute has the right shape */
int reverse_coa_token(const struct tlv *attr, char *token) {
    if (!attr || attr->t != RAD_ExtAttr_Operator_NAS_Identifier.t || attr->l != REVERSE_COA_TOKEN_LEN + 1 ||
        attr->v[0] != RAD_ExtAttr_Operator_NAS_Identifier.s)
        return 0;
    memcpy(token, attr->v + 1, REVERSE_COA_TOKEN_LEN);
    token[REVERSE_COA_TOKEN_LEN] = '\0';
    return 1;
}

/* rfc 8559 3.4: access and accounting requests only, once, only with operator-name.
   the value is the connection's token as learn_nas_identity() set it from this request */
int add_operator_nas_identifier(struct client *from, struct radmsg *msg) {
    struct tlv *attr;
    char token[REVERSE_COA_TOKEN_LEN + 1];

    if (!radmsg_gettype(msg, RAD_Attr_Operator_Name) || radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier))
        return 1;
    pthread_mutex_lock(&from->lock);
    memcpy(token, from->token, sizeof(token));
    pthread_mutex_unlock(&from->lock);
    attr = makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, token);
    if (!attr || !radmsg_add(msg, attr, 0)) {
        freetlv(attr);
        return 0;
    }
    debug(DBG_DBG, "add_operator_nas_identifier: added %s to %s (id %d) from client %s", token,
          radmsgtype2string(msg->code), msg->id, from->conf->name);
    return 1;
}

/* rfc 8559 4.2: removed before the packet reaches the nas */
void strip_operator_attrs(struct radmsg *msg) {
    struct list_node *n, *p = NULL;
    struct tlv *attr;

    n = list_first(msg->attrs);
    while (n) {
        attr = (struct tlv *)n->data;
        if (attr->t == RAD_Attr_Operator_Name ||
            (attr->t == RAD_ExtAttr_Operator_NAS_Identifier.t && attr->l > 0 && attr->v[0] == RAD_ExtAttr_Operator_NAS_Identifier.s)) {
            list_removedata(msg->attrs, attr);
            freetlv(attr);
            n = p ? list_next(p) : list_first(msg->attrs);
        } else {
            p = n;
            n = list_next(n);
        }
    }
}

/* rfc 8559 4.2: the packet sent to the nas names it, by NASidentifier or by address */
static int add_nas_identification(struct client *to, struct radmsg *msg) {
    struct tlv *attr = NULL;
    struct sockaddr_in6 *sin6;

    if (radmsg_gettype(msg, RAD_Attr_NAS_Identifier) || radmsg_gettype(msg, RAD_Attr_NAS_IP_Address) ||
        radmsg_gettype(msg, RAD_Attr_NAS_IPv6_Address))
        return 1;
    if (to->conf->nas_identifier)
        attr = maketlv(RAD_Attr_NAS_Identifier, strlen(to->conf->nas_identifier), to->conf->nas_identifier);
    else if (to->addr && to->addr->sa_family == AF_INET)
        attr = maketlv(RAD_Attr_NAS_IP_Address, 4, &((struct sockaddr_in *)to->addr)->sin_addr);
    else if (to->addr && to->addr->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *)to->addr;
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
            attr = maketlv(RAD_Attr_NAS_IP_Address, 4, &sin6->sin6_addr.s6_addr[12]);
        else
            attr = maketlv(RAD_Attr_NAS_IPv6_Address, 16, &sin6->sin6_addr);
    } else
        return 1;
    if (!attr || !radmsg_add(msg, attr, 0)) {
        freetlv(attr);
        return 0;
    }
    return 1;
}

/* a client with NASidentifier is the nas, as is any udp client; the others are proxies */
static int reverse_coa_final_hop(struct client *client) {
    return client->conf->type == RAD_UDP || client->conf->nas_identifier != NULL;
}

static void expire_reverse_coa_rqs(struct client *client) {
    struct timeval now;
    struct rqout *rqout;
    int i;

    if (!client->reverse_coa_rqs)
        return;
    gettimeofday(&now, NULL);
    for (i = 0; i < MAX_REQUESTS; i++) {
        rqout = &client->reverse_coa_rqs[i];
        if (rqout->rq && rqout->expiry.tv_sec > 0 && now.tv_sec > rqout->expiry.tv_sec) {
            debug(DBG_NOTICE, "expire_reverse_coa_rqs: no answer to reverse coa request id %d from client %s, dropping",
                  i, client->conf->name);
            clear_rqout(client, rqout);
        }
    }
}

static int send_reverse_coa_nak(struct server *server, struct radmsg *req, uint32_t error_cause,
                                uint8_t **out_buf, int *out_len) {
    struct radmsg *nak;
    uint8_t nakcode;
    uint8_t *buf = NULL;
    uint8_t ma_zeros[16] = {0};
    int radlen;

    if (out_buf)
        *out_buf = NULL;
    if (out_len)
        *out_len = 0;

    nakcode = coa_nak_code(req->code);
    nak = radmsg_init(nakcode, req->id, req->auth);
    if (!nak) {
        debug(DBG_ERR, "send_reverse_coa_nak: malloc failed");
        return 0;
    }
    if (!radmsg_add(nak, make_error_cause_tlv(error_cause), 0) || radmsg_copy_attrs(nak, req, RAD_Attr_Proxy_State) < 0 ||
        !radmsg_add(nak, maketlv(RAD_Attr_Message_Authenticator, 16, ma_zeros), 0)) {
        debug(DBG_ERR, "send_reverse_coa_nak: malloc failed");
        radmsg_free(nak);
        return 0;
    }
    radlen = radmsg2buf(nak, server->conf->secret, server->conf->secret_len, &buf);
    if (radlen <= 0) {
        debug(DBG_ERR, "send_reverse_coa_nak: radmsg2buf failed");
        radmsg_free(nak);
        return 0;
    }
    debug(DBG_INFO, "send_reverse_coa_nak: sending %s (id %d) with Error-Cause %u to server %s",
          radmsgtype2string(nakcode), nak->id, error_cause, server->conf->name);
    server->conf->pdef->clientradput(server, buf, radlen);
    if (out_buf && out_len) {
        *out_buf = buf;
        *out_len = radlen;
    } else
        free(buf);
    radmsg_free(nak);
    return 1;
}

/* sends a copy of msg to the client with a new id and keeps it for the response.
   from_server or origin says where the response goes. returns 0 when sent, else the
   Error-Cause for the nak. the caller holds the client's route locked, so the client
   cannot go away meanwhile */
static int send_coa_to_client(struct server *from_server, struct request *origin, struct client *to_client,
                              struct radmsg *msg, struct reverse_coa_sent *sent) {
    struct request *rq;
    struct rqout *rqout;
    struct radmsg *copy;
    uint8_t newid;
    int attempts, replybuflen;
    int final_hop = reverse_coa_final_hop(to_client);

    if (!to_client->reverse_coa_route) {
        debug(DBG_WARN, "send_coa_to_client: client %s not configured for reverse coa", to_client->conf->name);
        return RAD_Err_Request_Not_Routable;
    }
    if (origin && origin->from == to_client) {
        debug(DBG_INFO, "send_coa_to_client: %s (id %d) from client %s would go back to its sender, ignoring",
              radmsgtype2string(msg->code), msg->id, to_client->conf->name);
        return RAD_Err_Request_Not_Routable;
    }

    copy = radmsg_dup(msg);
    if (!copy) {
        debug(DBG_ERR, "send_coa_to_client: malloc failed");
        return RAD_Err_Resources_Unavailable;
    }
    if (final_hop) {
        strip_operator_attrs(copy);
        if (!add_nas_identification(to_client, copy)) {
            radmsg_free(copy);
            return RAD_Err_Resources_Unavailable;
        }
    }
    /* drop the previous hop's message-authenticator before signing, as radsrv() does */
    if (!ensuremsgauthfront(copy)) {
        radmsg_free(copy);
        return RAD_Err_Resources_Unavailable;
    }
    rq = newrequest();
    if (!rq) {
        radmsg_free(copy);
        return RAD_Err_Resources_Unavailable;
    }

    pthread_mutex_lock(&to_client->lock);
    if (!to_client->reverse_coa_rqs)
        to_client->reverse_coa_rqs = calloc(MAX_REQUESTS, sizeof(struct rqout));
    if (!to_client->reverse_coa_rqs) {
        pthread_mutex_unlock(&to_client->lock);
        debug(DBG_ERR, "send_coa_to_client: malloc failed");
        freerq(rq);
        radmsg_free(copy);
        return RAD_Err_Resources_Unavailable;
    }
    expire_reverse_coa_rqs(to_client);
    for (attempts = 0; attempts < MAX_REQUESTS; attempts++) {
        newid = to_client->reverse_coa_nextid++;
        rqout = &to_client->reverse_coa_rqs[newid];
        if (!rqout->rq)
            break;
    }
    if (attempts >= MAX_REQUESTS) {
        pthread_mutex_unlock(&to_client->lock);
        debug(DBG_WARN, "send_coa_to_client: no free id for client %s", to_client->conf->name);
        freerq(rq);
        radmsg_free(copy);
        return RAD_Err_Resources_Unavailable;
    }

    rq->rqid = msg->id;
    memcpy(rq->rqauth, msg->auth, 16);
    rq->to = from_server;
    rq->origin = origin ? newrqref(origin) : NULL;
    rq->from = to_client;
    rq->udpsock = to_client->sock;
    rq->newid = newid;
    /* a udp client gets it on its coa port, not the port it last sent from */
    if (to_client->conf->type == RAD_UDP && to_client->addr) {
        rq->to_override = malloc(sizeof(struct sockaddr_storage));
        if (!rq->to_override) {
            pthread_mutex_unlock(&to_client->lock);
            debug(DBG_ERR, "send_coa_to_client: malloc failed");
            freerq(rq);
            radmsg_free(copy);
            return RAD_Err_Resources_Unavailable;
        }
        memset(rq->to_override, 0, sizeof(struct sockaddr_storage));
        memcpy(rq->to_override, to_client->addr, SOCKADDRP_SIZE(to_client->addr));
        port_set((struct sockaddr *)rq->to_override, (uint16_t)to_client->conf->coaport);
    }
    copy->id = newid;
    memset(copy->auth, 0, 16); /* radmsgsign computes the request authenticator in place */
    rq->msg = copy;
    /* encode under the lock so sentauth is set before rqout->rq is visible */
    replybuflen = radmsg2buf(rq->msg, to_client->conf->secret, to_client->conf->secret_len, &rq->replybuf);
    if (replybuflen <= 0 || !rq->replybuf) {
        pthread_mutex_unlock(&to_client->lock);
        debug(DBG_ERR, "send_coa_to_client: radmsg2buf failed for client %s", to_client->conf->name);
        freerq(rq);
        return RAD_Err_Resources_Unavailable;
    }
    rq->replybuflen = replybuflen;
    rqout->rq = rq;
    to_client->reverse_coa_pending++;
    gettimeofday(&rqout->expiry, NULL);
    rqout->expiry.tv_sec += to_client->conf->reverse_coa_timeout;
    memcpy(rqout->sentauth, rq->replybuf + 4, 16);
    pthread_mutex_unlock(&to_client->lock);

    debug(DBG_INFO, "send_coa_to_client: forwarding %s (id %d -> %d) to client %s%s",
          radmsgtype2string(copy->code), msg->id, newid, to_client->conf->name, final_hop ? " (nas)" : "");
    if (sendreply(newrqref(rq)) < 1) {
        pthread_mutex_lock(&to_client->lock);
        if (rqout->rq == rq)
            clear_rqout(to_client, rqout);
        pthread_mutex_unlock(&to_client->lock);
        return RAD_Err_Resources_Unavailable;
    }
    if (sent) {
        sent->route = to_client->reverse_coa_route;
        sent->id = newid;
    }
    return 0;
}

/* sends down a route taken from the registry, the caller holds a reference which
   moves to sent when the request went out */
static int send_to_route(struct server *server, struct request *origin, struct reverse_coa_route *route,
                         struct radmsg *msg, struct reverse_coa_sent *sent) {
    int result = RAD_Err_Request_Not_Routable;

    pthread_mutex_lock(&route->refmutex);
    if (route->target)
        result = send_coa_to_client(server, origin, route->target, msg, sent);
    pthread_mutex_unlock(&route->refmutex);
    if (result)
        reverse_coa_route_deref(route);
    return result;
}

/* the nas address named in the request: NAS-IP-Address or NAS-IPv6-Address, port 0 */
int reverse_coa_nas_addr(struct radmsg *msg, struct sockaddr_storage *out) {
    struct tlv *attr;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    memset(out, 0, sizeof(*out));
    attr = radmsg_gettype(msg, RAD_Attr_NAS_IP_Address);
    if (attr && attr->l == 4) {
        sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, attr->v, 4);
        return 1;
    }
    attr = radmsg_gettype(msg, RAD_Attr_NAS_IPv6_Address);
    if (attr && attr->l == 16) {
        sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, attr->v, 16);
        return 1;
    }
    return 0;
}

/* returns 1 if NAS-Identifier or Operator-NAS-Identifier equals the block's NASidentifier,
   0 if not, -1 if the request carries neither */
static int conf_nas_identifier_match(struct clsrvconf *conf, struct radmsg *msg) {
    struct tlv *attr;
    size_t len;
    int seen = 0;

    if (!conf->nas_identifier)
        return 0;
    len = strlen(conf->nas_identifier);
    attr = radmsg_gettype(msg, RAD_Attr_NAS_Identifier);
    if (attr) {
        seen = 1;
        if (attr->l == len && !memcmp(attr->v, conf->nas_identifier, len))
            return 1;
    }
    attr = radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier);
    if (attr) {
        seen = 1;
        if (attr->l == len + 1 && !memcmp(attr->v + 1, conf->nas_identifier, len))
            return 1;
    }
    return seen ? 0 : -1;
}

/* the single host a client block names, if it names exactly one */
static int conf_host_addr(struct clsrvconf *conf, struct sockaddr_storage *out) {
    struct hostportres *hp;

    if (!conf->hostports || list_count(conf->hostports) != 1)
        return 0;
    hp = (struct hostportres *)list_first(conf->hostports)->data;
    if (!hp || hp->prefixlen != 255 || !hp->addrinfo || !hp->addrinfo->ai_addr)
        return 0;
    memset(out, 0, sizeof(*out));
    memcpy(out, hp->addrinfo->ai_addr, hp->addrinfo->ai_addrlen);
    return 1;
}

#ifdef RADPROT_UDP
/* a udp nas with no client entry right now (idle, or never seen): find or create the
   entry for addr in its client block and send */
static int send_to_udp_block(struct server *server, struct request *origin, struct clsrvconf *conf,
                             struct sockaddr *addr, struct radmsg *msg, struct reverse_coa_sent *sent) {
    struct list_node *node;
    struct client *client = NULL;
    struct reverse_coa_route *route = NULL;
    struct timeval now;
    char tmp[INET6_ADDRSTRLEN];
    int sock;

    sock = udplistenersocket(addr->sa_family);
    if (sock < 0) {
        debug(DBG_WARN, "send_to_udp_block: no udp listener for the address family of %s", addr2string(addr, tmp, sizeof(tmp)));
        return RAD_Err_Request_Not_Routable;
    }
    pthread_mutex_lock(conf->lock);
    for (node = list_first(conf->clients); node; node = list_next(node)) {
        client = (struct client *)node->data;
        if (client->sock == sock && addr_equal_ip(client->addr, addr))
            break;
        client = NULL;
    }
    if (!client) {
        client = addclient(conf, sock, addr, NULL, 0);
        if (client)
            debug(DBG_INFO, "send_to_udp_block: created client %s (%s) for reverse coa", conf->name, addr2string(addr, tmp, sizeof(tmp)));
    }
    if (client) {
        gettimeofday(&now, NULL);
        client->expiry = now.tv_sec + 60;
        route = client->reverse_coa_route;
        reverse_coa_route_ref(route);
    }
    pthread_mutex_unlock(conf->lock);
    if (!client) {
        debug(DBG_ERR, "send_to_udp_block: addclient failed for %s", conf->name);
        return RAD_Err_Resources_Unavailable;
    }
    return send_to_route(server, origin, route, msg, sent);
}

/* the client block covering the address in NAS-IP-Address or NAS-IPv6-Address, or the
   block naming a single host whose NASidentifier the request names. with a realm, the
   block must declare it with ReverseCoAOperatorRealm; a block declaring it for another nas
   gives 403 */
static int try_send_to_udp_block(struct server *server, struct request *origin, const char *realm,
                                 struct radmsg *msg, struct reverse_coa_sent *sent) {
    struct sockaddr_storage addr;
    struct clsrvconf *conf = NULL;
    struct list_node *cur = NULL;
    char tmp[INET6_ADDRSTRLEN];
    int result = RAD_Err_Request_Not_Routable;

    if (reverse_coa_nas_addr(msg, &addr)) {
        conf = find_clconf(RAD_UDP, (struct sockaddr *)&addr, NULL, NULL);
        if (conf && realm && !conf_realm_matches(conf, realm))
            conf = NULL;
        if (conf && conf->nas_identifier && conf_nas_identifier_match(conf, msg) == 0) {
            debug(DBG_INFO, "try_send_to_udp_block: client %s matches %s but NASidentifier differs", conf->name, addr2string((struct sockaddr *)&addr, tmp, sizeof(tmp)));
            return RAD_Err_NAS_Identification_Mismatch;
        }
    } else {
        while ((conf = find_clconf_type(RAD_UDP, &cur)))
            if (conf_nas_identifier_match(conf, msg) == 1 && conf_host_addr(conf, &addr) && (!realm || conf_realm_matches(conf, realm)))
                break;
    }
    if (conf) {
        if (conf->nas_identifier || conf->add_operator_nas_id || conf->reverse_coa_realms)
            return send_to_udp_block(server, origin, conf, (struct sockaddr *)&addr, msg, sent);
        debug(DBG_INFO, "try_send_to_udp_block: client %s not configured for reverse coa", conf->name);
        return result;
    }
    /* rfc 8559 3.3: the realm is ours but the nas is not known */
    if (realm)
        for (cur = NULL; (conf = find_clconf_type(RAD_UDP, &cur));)
            if (conf_realm_matches(conf, realm))
                result = RAD_Err_NAS_Identification_Mismatch;
    return result;
}
#endif

/* the nas named by the token we added on the way out: the connection whose last
   request set that token, see reverse_coa_nastoken(); or a udp block whose name and
   the nas identification in the request give it, the nas address then picks the entry.
   only nases (final hops) are looked at. two connections of one nas (hostapd keeps one
   for authentication and one for accounting) share the token, as do two nases on one
   certificate sending the same NAS-Identifier: the nas the request names (rfc 5176
   section 3) goes first, then the connection that sent a request most recently, which
   is the live one after a reconnection */
static int try_send_to_token_client(struct server *server, struct request *origin, struct radmsg *msg, struct reverse_coa_sent *sent) {
    struct reverse_coa_route *route = NULL, *named = NULL, *candidate;
    struct list_node *node;
    struct sockaddr_storage addr;
    char token[REVERSE_COA_TOKEN_LEN + 1];
    time_t newest = 0, seen;
    int has_addr, matches = 0, same;
#ifdef RADPROT_UDP
    struct clsrvconf *conf;
    struct list_node *cur = NULL;
    char blocktoken[REVERSE_COA_TOKEN_LEN + 1];
#endif

    if (!reverse_coa_token(radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier), token))
        return RAD_Err_Request_Not_Routable;
    has_addr = reverse_coa_nas_addr(msg, &addr);

    pthread_mutex_lock(&realm_reverse_coa_lock);
    for (node = list_first(reverse_coa_nas_routes); node && !named; node = list_next(node)) {
        candidate = (struct reverse_coa_route *)node->data;
        pthread_mutex_lock(&candidate->refmutex);
        if (candidate->target && reverse_coa_final_hop(candidate->target)) {
            pthread_mutex_lock(&candidate->target->lock);
            same = !strcmp(candidate->target->token, token);
            seen = candidate->target->last_request;
            pthread_mutex_unlock(&candidate->target->lock);
            if (same && (candidate->target->conf->type != RAD_UDP || !has_addr || addr_equal_ip(candidate->target->addr, (struct sockaddr *)&addr))) {
                matches++;
                if (match_nas_identifier(candidate->target, msg))
                    named = candidate;
                else if (!route || seen > newest) {
                    route = candidate;
                    newest = seen;
                }
            }
        }
        pthread_mutex_unlock(&candidate->refmutex);
    }
    if (named)
        route = named;
    if (route)
        reverse_coa_route_ref(route);
    pthread_mutex_unlock(&realm_reverse_coa_lock);
    if (route) {
        if (matches > 1)
            debug(DBG_DBG, "try_send_to_token_client: %d connections carry the operator-nas-identifier, %s", matches,
                  named ? "the nas named in the request is one of them" : "taking the one that sent a request most recently");
        else
            debug(DBG_DBG, "try_send_to_token_client: operator-nas-identifier names a client connection");
        return send_to_route(server, origin, route, msg, sent);
    }
#ifdef RADPROT_UDP
    /* a udp nas has no connection: its block name and what the request says the nas is
       give the token the block added on the way out */
    if (has_addr)
        while ((conf = find_clconf_type(RAD_UDP, &cur)))
            if (addressmatches(conf->hostports, (struct sockaddr *)&addr, 0, NULL) &&
                reverse_coa_nastoken(blocktoken, conf->name, msg, NULL) && !strcmp(blocktoken, token))
                return send_to_udp_block(server, origin, conf, (struct sockaddr *)&addr, msg, sent);
#endif
    debug(DBG_INFO, "try_send_to_token_client: no nas carries the operator-nas-identifier");
    return RAD_Err_Request_Not_Routable;
}

/* the clients registered for the operator-name realm: the nas named in the request
   if one of them is it, else a proxy; rfc 8559 3.3 when only nases are registered
   and none is named. literal realm values are tried before regexps, so a catch-all
   regexp does not take requests meant for a client registered by name. several
   proxies are tried in the order they registered, the next when a send fails */
static int try_send_to_realm_clients(struct server *server, struct request *origin, const char *realm,
                                     struct radmsg *msg, struct reverse_coa_sent *sent) {
    struct reverse_coa_route *nas = NULL, *proxies[MAX_REVERSE_COA_FAILOVER], *route;
    struct reverse_coa_realm *r;
    struct list_node *rnode, *node;
    int nases = 0, nproxies = 0, i, pass, result = RAD_Err_Request_Not_Routable;

    pthread_mutex_lock(&realm_reverse_coa_lock);
    for (pass = 0; pass < 2; pass++) {
        for (rnode = list_first(reverse_coa_realm_list); rnode; rnode = list_next(rnode)) {
            r = (struct reverse_coa_realm *)rnode->data;
            if ((r->value[0] == '/') != pass || regexec(&r->regex, realm, 0, NULL, 0))
                continue;
            for (node = list_first(r->routes); node; node = list_next(node)) {
                route = (struct reverse_coa_route *)node->data;
                pthread_mutex_lock(&route->refmutex);
                if (route->target) {
                    /* refmutex held, so the reference is taken directly */
                    if (reverse_coa_final_hop(route->target)) {
                        nases++;
                        if (!nas && match_nas_identifier(route->target, msg)) {
                            nas = route;
                            route->refcount++;
                        }
                    } else if (nproxies < MAX_REVERSE_COA_FAILOVER) {
                        proxies[nproxies++] = route;
                        route->refcount++;
                    }
                }
                pthread_mutex_unlock(&route->refmutex);
            }
        }
    }
    pthread_mutex_unlock(&realm_reverse_coa_lock);

    if (nas) {
        debug(DBG_DBG, "try_send_to_realm_clients: realm %s, the nas named in the request is registered", realm);
        result = send_to_route(server, origin, nas, msg, sent);
    } else if (!nproxies)
        result = nases ? RAD_Err_NAS_Identification_Mismatch : RAD_Err_Request_Not_Routable;
    for (i = 0; i < nproxies; i++) {
        if (result && result != RAD_Err_NAS_Identification_Mismatch) {
            debug(DBG_DBG, "try_send_to_realm_clients: realm %s, trying a proxy", realm);
            result = send_to_route(server, origin, proxies[i], msg, sent);
        } else
            reverse_coa_route_deref(proxies[i]);
    }
    return result;
}

/* a client the request names by nas identity, for requests without operator-name */
static int try_send_to_nas_client(struct server *server, struct request *origin, struct radmsg *msg, struct reverse_coa_sent *sent) {
    struct reverse_coa_route *route = NULL, *candidate;
    struct list_node *node;

    pthread_mutex_lock(&realm_reverse_coa_lock);
    for (node = list_first(reverse_coa_nas_routes); node && !route; node = list_next(node)) {
        candidate = (struct reverse_coa_route *)node->data;
        pthread_mutex_lock(&candidate->refmutex);
        if (candidate->target && match_nas_identifier(candidate->target, msg))
            route = candidate;
        pthread_mutex_unlock(&candidate->refmutex);
    }
    if (route)
        reverse_coa_route_ref(route);
    pthread_mutex_unlock(&realm_reverse_coa_lock);
    if (!route)
        return RAD_Err_Request_Not_Routable;
    debug(DBG_DBG, "try_send_to_nas_client: the nas named in the request is a client");
    return send_to_route(server, origin, route, msg, sent);
}

/* by token, then the operator-name realm (rfc 8559 3.2); a request without
   operator-name is routed by nas identity. returns 0 when sent, else the Error-Cause
   for the nak */
static int dispatch_reverse_coa(struct server *server, struct request *origin, struct radmsg *msg, struct reverse_coa_sent *sent) {
    char realm_buf[256];
    char *realm = extract_operator_realm(msg, realm_buf, sizeof(realm_buf));
    int result;

    sent->route = NULL;
    /* rfc 8559 3.4: operator-nas-identifier only counts next to operator-name */
    if (realm && !try_send_to_token_client(server, origin, msg, sent))
        return 0;
    if (realm) {
        result = try_send_to_realm_clients(server, origin, realm, msg, sent);
#ifdef RADPROT_UDP
        /* a request from a client never creates client entries */
        if (result == RAD_Err_Request_Not_Routable && !origin)
            result = try_send_to_udp_block(server, origin, realm, msg, sent);
#endif
        if (result)
            debug_limit(DBG_INFO, "dispatch_reverse_coa: no route for %s (id %d) with operator-name realm %s, Error-Cause %d",
                        radmsgtype2string(msg->code), msg->id, realm, result);
        return result;
    }
    result = try_send_to_nas_client(server, origin, msg, sent);
#ifdef RADPROT_UDP
    if (result == RAD_Err_Request_Not_Routable && !origin)
        result = try_send_to_udp_block(server, origin, NULL, msg, sent);
#endif
    if (result)
        debug_limit(DBG_INFO, "dispatch_reverse_coa: no route for %s (id %d) without operator-name, Error-Cause %d",
                    radmsgtype2string(msg->code), msg->id, result);
    return result;
}

int _internal_dispatch_reverse_coa(struct server *server, struct request *origin, struct radmsg *msg) { struct reverse_coa_sent sent; int result = dispatch_reverse_coa(server, origin, msg, &sent); reverse_coa_route_deref(sent.route); return result; }

static void route_reverse_coa(struct server *server, struct radmsg *msg) {
    struct reverse_coa_sent sent;
    uint8_t *nakbuf = NULL;
    int naklen = 0, result;

    record_coa_dedup(server, msg->id, msg->auth);
    result = dispatch_reverse_coa(server, NULL, msg, &sent);
    if (!result) {
        record_coa_route(server, msg->id, msg->auth, &sent);
        radmsg_free(msg);
        return;
    }
    send_reverse_coa_nak(server, msg, result, &nakbuf, &naklen);
    if (nakbuf) {
        cache_coa_dedup_reply(server, msg->id, msg->auth, nakbuf, naklen);
        free(nakbuf);
    }
    radmsg_free(msg);
}

/* a request from a client with acceptCoA and reverseCoAFallback no coaServer took is
   offered to the reverse coa routes; the response answers rq through
   forward_coa_response(). returns 0 when sent, else the Error-Cause for the nak */
int route_reverse_coa_from_client(struct request *rq) {
    struct reverse_coa_sent sent;
    char realm[256];
    int result;

    /* the realm limits where a client's request can go, so it is required */
    if (!rq || !rq->msg || !rq->from || !extract_operator_realm(rq->msg, realm, sizeof(realm)))
        return RAD_Err_Request_Not_Routable;
    result = dispatch_reverse_coa(NULL, rq, rq->msg, &sent);
    reverse_coa_route_deref(sent.route);
    return result;
}

static void handle_reverse_coa_request(struct server *server, uint8_t *buf, int len) {
    struct radmsg *msg;

    msg = buf2radmsg(buf, len, server->conf->secret, server->conf->secret_len, NULL);
    if (!msg) {
        debug_limit(DBG_INFO, "handle_reverse_coa_request: message decode error (code %d, id %d ?) from server %s",
                    buf[0], buf[1], server->conf->name);
        return;
    }
    if (msg->authstate != RSP_RADMSG_VALID && msg->authstate != RSP_RADMSG_MSGAUTH_VALID) {
        debug_limit(DBG_WARN, "handle_reverse_coa_request: invalid %s in %s (id %d) from server %s, ignoring",
                    msg->authstate == RSP_RADMSG_MSGAUTH_INVALID ? "message-authenticator" : "request-authenticator",
                    radmsgtype2string(msg->code), msg->id, server->conf->name);
        radmsg_free(msg);
        return;
    }
    if (!event_timestamp_fresh(radmsg_gettype(msg, RAD_Attr_Event_Timestamp), REVERSE_COA_DEDUP_WINDOW)) {
        debug_limit(DBG_NOTICE, "handle_reverse_coa_request: stale event-timestamp in %s (id %d) from server %s, ignoring",
                    radmsgtype2string(msg->code), msg->id, server->conf->name);
        radmsg_free(msg);
        return;
    }

    expire_coa_dedup_entries(server);
    if (is_coa_duplicate(server, msg)) {
        radmsg_free(msg);
        return;
    }

    debug(DBG_INFO, "handle_reverse_coa_request: received %s (id %d) from server %s",
          radmsgtype2string(msg->code), msg->id, server->conf->name);
    route_reverse_coa(server, msg);
}

/* answers the request a reverse coa response belongs to: the server it came from,
   or the client whose request was routed down a reverse coa route. returns 1 if
   the response matched a pending request */
int forward_coa_response(struct client *from, struct radmsg *msg) {
    struct rqout *rqout;
    struct request *origin;
    struct server *to_server;
    struct radmsg *reply;
    struct tlv *errorcause;
    uint8_t sentcode, origid;
    uint8_t origauth[16];
    uint8_t *buf = NULL;
    int radlen;

    if (!from->reverse_coa_rqs)
        return 0;

    /* the originating server or client is freed under this lock, see freeserver()
       and removeclientrq(); held until the answer is on its way */
    pthread_mutex_lock(removeclientrqs_sendrq_freeserver_lock());
    pthread_mutex_lock(&from->lock);
    expire_reverse_coa_rqs(from);
    rqout = &from->reverse_coa_rqs[msg->id];
    if (!rqout->rq) {
        pthread_mutex_unlock(&from->lock);
        pthread_mutex_unlock(removeclientrqs_sendrq_freeserver_lock());
        debug_limit(DBG_INFO, "forward_coa_response: no pending reverse coa request with id %d from client %s, ignoring %s",
                    msg->id, from->conf->name, radmsgtype2string(msg->code));
        return 0;
    }
    sentcode = rqout->rq->replybuf[0];
    if (msg->code != (sentcode == RAD_CoA_Request ? RAD_CoA_ACK : RAD_Disconnect_ACK) &&
        msg->code != (sentcode == RAD_CoA_Request ? RAD_CoA_NAK : RAD_Disconnect_NAK)) {
        pthread_mutex_unlock(&from->lock);
        pthread_mutex_unlock(removeclientrqs_sendrq_freeserver_lock());
        debug(DBG_INFO, "forward_coa_response: %s (id %d) from client %s does not answer the %s sent, ignoring",
              radmsgtype2string(msg->code), msg->id, from->conf->name, radmsgtype2string(sentcode));
        return 0;
    }
    origin = rqout->rq->origin;
    rqout->rq->origin = NULL;
    to_server = rqout->rq->to;
    origid = rqout->rq->rqid;
    memcpy(origauth, rqout->rq->rqauth, 16);
    clear_rqout(from, rqout);
    pthread_mutex_unlock(&from->lock);

    errorcause = radmsg_gettype(msg, RAD_Attr_Error_Cause);
    if (errorcause && errorcause->l == 4)
        debug(DBG_INFO, "forward_coa_response: %s (id %d) from client %s with Error-Cause %u",
              radmsgtype2string(msg->code), msg->id, from->conf->name, tlv2longint(errorcause));

    reply = radmsg_dup(msg);
    if (reply) {
        reply->id = origid;
        memcpy(reply->auth, origauth, 16);
        if (!ensuremsgauthfront(reply)) {
            radmsg_free(reply);
            reply = NULL;
        }
    }
    if (!reply) {
        debug(DBG_ERR, "forward_coa_response: malloc failed");
        if (origin)
            freerq(origin);
    } else if (origin) {
        if (!origin->from) {
            debug(DBG_INFO, "forward_coa_response: client that sent request id %d is gone, dropping %s",
                  origid, radmsgtype2string(msg->code));
            radmsg_free(reply);
            freerq(origin);
        } else {
            debug(DBG_INFO, "forward_coa_response: %s (id %d) from client %s answers request id %d from client %s",
                  radmsgtype2string(msg->code), msg->id, from->conf->name, origid, origin->from->conf->name);
            radmsg_free(origin->msg);
            origin->msg = reply;
            if (sendreply(origin) < 1)
                debug(DBG_ERR, "forward_coa_response: answering request id %d failed", origid);
        }
    } else {
        radlen = radmsg2buf(reply, to_server->conf->secret, to_server->conf->secret_len, &buf);
        radmsg_free(reply);
        if (radlen <= 0)
            debug(DBG_ERR, "forward_coa_response: radmsg2buf failed");
        else {
            debug(DBG_INFO, "forward_coa_response: %s (id %d) from client %s answers request id %d from server %s",
                  radmsgtype2string(msg->code), msg->id, from->conf->name, origid, to_server->conf->name);
            if (!to_server->conf->pdef->clientradput(to_server, buf, radlen))
                debug(DBG_WARN, "forward_coa_response: sending %s (id %d) to server %s failed",
                      radmsgtype2string(msg->code), origid, to_server->conf->name);
            cache_coa_dedup_reply(to_server, origid, origauth, buf, radlen);
            free(buf);
        }
    }
    pthread_mutex_unlock(removeclientrqs_sendrq_freeserver_lock());
    return 1;
}

void invalidate_reverse_coa_rqs_for_server(struct server *server, struct list *clconfs) {
    struct list_node *confentry, *cliententry;
    struct clsrvconf *conf;
    struct client *client;
    int i, cleaned = 0;

    for (confentry = list_first(clconfs); confentry; confentry = list_next(confentry)) {
        conf = (struct clsrvconf *)confentry->data;
        if (!conf || !conf->clients)
            continue;

        pthread_mutex_lock(conf->lock);
        for (cliententry = list_first(conf->clients); cliententry; cliententry = list_next(cliententry)) {
            client = (struct client *)cliententry->data;
            if (!client || !client->reverse_coa_rqs)
                continue;

            pthread_mutex_lock(&client->lock);
            for (i = 0; i < MAX_REQUESTS; i++) {
                struct rqout *rqout = &client->reverse_coa_rqs[i];
                if (rqout->rq && rqout->rq->to == server) {
                    debug(DBG_DBG, "invalidate_reverse_coa_rqs_for_server: clearing request id %d from client %s (server %s disconnecting)",
                          i, client->conf->name, server->conf->name);
                    clear_rqout(client, rqout);
                    cleaned++;
                }
            }
            pthread_mutex_unlock(&client->lock);
        }
        pthread_mutex_unlock(conf->lock);
    }

    if (cleaned > 0)
        debug(DBG_INFO, "invalidate_reverse_coa_rqs_for_server: cleared %d pending requests for server %s",
              cleaned, server->conf->name);
}

int lookup_reverse_coa_rqauth(struct client *from, uint8_t *buf, int buflen, uint8_t *out_auth) {
    uint8_t resp_id;
    struct rqout *rqout;

    if (buflen < 2 || !from->reverse_coa_rqs)
        return 0;
    if (!IS_COA_RESPONSE(buf[0]))
        return 0;

    resp_id = buf[1];
    pthread_mutex_lock(&from->lock);
    rqout = &from->reverse_coa_rqs[resp_id];
    if (rqout->rq) {
        memcpy(out_auth, rqout->sentauth, 16);
        pthread_mutex_unlock(&from->lock);
        return 1;
    }
    pthread_mutex_unlock(&from->lock);
    return 0;
}

int try_handle_reverse_coa_request(struct server *server, unsigned char *buf, int len) {
    uint8_t code = buf[0];

    if (IS_COA_REQUEST(code)) {
        if (!server->conf->accept_reverse_coa) {
            debug_limit(DBG_INFO, "try_handle_reverse_coa_request: %s from server %s ignored, acceptReverseCoA not enabled",
                        radmsgtype2string(code), server->conf->name);
        } else {
            handle_reverse_coa_request(server, buf, len);
        }
        free(buf);
        return 1;
    }
    return 0;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
