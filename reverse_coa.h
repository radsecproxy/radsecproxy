/* Copyright (c) 2026, Nova Labs */
/* See LICENSE for licensing information. */

#ifndef _REVERSE_COA_H
#define _REVERSE_COA_H

#include "radsecproxy.h"

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)

void init_reverse_coa(void);
void register_reverse_coa_client(struct client *client);
void unregister_reverse_coa_client(struct client *client);
int forward_coa_response(struct client *from, struct radmsg *msg);
void invalidate_reverse_coa_rqs_for_server(struct server *server, struct list *clconfs);
void free_reverse_coa_rqs(struct client *client);
int lookup_reverse_coa_rqauth(struct client *from, uint8_t *buf, int buflen, uint8_t *out_auth);
int try_handle_reverse_coa_request(struct server *server, unsigned char *buf, int len);
void drain_coa_dedup(struct server *server);
struct reverse_coa_route *reverse_coa_route_new(struct client *target);
void reverse_coa_route_deref(struct reverse_coa_route *route);

#else

static inline void init_reverse_coa(void) {}
static inline void register_reverse_coa_client(struct client *client) { (void)client; }
static inline void unregister_reverse_coa_client(struct client *client) { (void)client; }
static inline int forward_coa_response(struct client *from, struct radmsg *msg) { (void)from; (void)msg; return 0; }
static inline void invalidate_reverse_coa_rqs_for_server(struct server *server, struct list *clconfs) { (void)server; (void)clconfs; }
static inline void free_reverse_coa_rqs(struct client *client) { (void)client; }
static inline int lookup_reverse_coa_rqauth(struct client *from, uint8_t *buf, int buflen, uint8_t *out_auth) { (void)from; (void)buf; (void)buflen; (void)out_auth; return 0; }
static inline int try_handle_reverse_coa_request(struct server *server, unsigned char *buf, int len) { (void)server; (void)buf; (void)len; return 0; }
static inline void drain_coa_dedup(struct server *server) { (void)server; }
static inline struct reverse_coa_route *reverse_coa_route_new(struct client *target) { (void)target; return NULL; }
static inline void reverse_coa_route_deref(struct reverse_coa_route *route) { (void)route; }

#endif

#endif /* _REVERSE_COA_H */
