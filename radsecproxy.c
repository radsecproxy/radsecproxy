/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2013,2015-2016, NORDUnet A/S */
/* See LICENSE for licensing information. */

/* For UDP there is one server instance consisting of udpserverrd and udpserverth
 *              rd is responsible for init and launching wr
 * For TLS there is a server instance that launches tlsserverrd for each TLS peer
 *          each tlsserverrd launches tlsserverwr
 * For each UDP/TLS peer there is clientrd and clientwr, clientwr is responsible
 *          for init and launching rd
 *
 * serverrd will receive a request, processes it and puts it in the requestq of
 *          the appropriate clientwr
 * clientwr monitors its requestq and sends requests
 * clientrd looks for responses, processes them and puts them in the replyq of
 *          the peer the request came from
 * serverwr monitors its reply and sends replies
 *
 * In addition to the main thread, we have:
 * If UDP peers are configured, there will be 2 + 2 * #peers UDP threads
 * If TLS peers are configured, there will initially be 2 * #peers TLS threads
 * For each TLS peer connecting to us there will be 2 more TLS threads
 *       This is only for connected peers
 * Example: With 3 UDP peers and 30 TLS peers, there will be a max of
 *          1 + (2 + 2 * 3) + (2 * 30) + (2 * 30) = 129 threads
 */

/* Bugs:
 * May segfault when dtls connections go down? More testing needed
 * Remove expired stuff from clients request list?
 * Multiple outgoing connections if not enough IDs? (multiple servers per conf?)
 * Useful for TCP accounting? Now we require separate server config for alt port
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#if defined(HAVE_MALLOPT)
#include <malloc.h>
#endif
#ifdef SYS_SOLARIS9
#include <fcntl.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <regex.h>
#include <libgen.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <nettle/md5.h>
#include "debug.h"
#include "hash.h"
#include "util.h"
#include "hostport.h"
#include "radsecproxy.h"
#include "udp.h"
#include "tcp.h"
#include "tls.h"
#include "dtls.h"
#include "fticks.h"
#include "fticks_hashmac.h"

static struct options options;
static struct list *clconfs, *srvconfs;
static struct list *realms;

#ifdef __CYGWIN__
extern int __declspec(dllimport) optind;
extern char __declspec(dllimport) *optarg;
#else
extern int optind;
extern char *optarg;
#endif
static const struct protodefs *protodefs[RAD_PROTOCOUNT];
pthread_attr_t pthread_attr;

/* minimum required declarations to avoid reordering code */
struct realm *adddynamicrealmserver(struct realm *realm, char *id);
int dynamicconfig(struct server *server);
int confserver_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
void freerealm(struct realm *realm);
void freeclsrvconf(struct clsrvconf *conf);
void freerq(struct request *rq);
void freerqoutdata(struct rqout *rqout);
void rmclientrq(struct request *rq, uint8_t id);

static const struct protodefs *(*protoinits[])(uint8_t) = { udpinit, tlsinit, tcpinit, dtlsinit };

uint8_t protoname2int(const char *name) {
    uint8_t i;

    for (i = 0; i < RAD_PROTOCOUNT; i++)
	if (protodefs[i] && protodefs[i]->name && !strcasecmp(protodefs[i]->name, name))
	    return i;
    return 255;
}

/* returns 1 if the len first bits are equal, else 0 */
int prefixmatch(void *a1, void *a2, uint8_t len) {
    static uint8_t mask[] = { 0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
    uint8_t r, l = len / 8;
    if (l && memcmp(a1, a2, l))
	return 0;
    r = len % 8;
    if (!r)
	return 1;
    return (((uint8_t *)a1)[l] & mask[r]) == (((uint8_t *)a2)[l] & mask[r]);
}

/* returns next config with matching address, or NULL */
struct clsrvconf *find_conf(uint8_t type, struct sockaddr *addr, struct list *confs, struct list_node **cur, uint8_t server_p) {
    struct list_node *entry;
    struct clsrvconf *conf;

    for (entry = (cur && *cur ? list_next(*cur) : list_first(confs)); entry; entry = list_next(entry)) {
	conf = (struct clsrvconf *)entry->data;
	if (conf->type == type && addressmatches(conf->hostports, addr, server_p)) {
	    if (cur)
		*cur = entry;
	    return conf;
	}
    }
    return NULL;
}

struct clsrvconf *find_clconf(uint8_t type, struct sockaddr *addr, struct list_node **cur) {
    return find_conf(type, addr, clconfs, cur, 0);
}

struct clsrvconf *find_srvconf(uint8_t type, struct sockaddr *addr, struct list_node **cur) {
    return find_conf(type, addr, srvconfs, cur, 1);
}

/* returns next config of given type, or NULL */
struct clsrvconf *find_clconf_type(uint8_t type, struct list_node **cur) {
    struct list_node *entry;
    struct clsrvconf *conf;

    for (entry = (cur && *cur ? list_next(*cur) : list_first(clconfs)); entry; entry = list_next(entry)) {
	conf = (struct clsrvconf *)entry->data;
	if (conf->type == type) {
	    if (cur)
		*cur = entry;
	    return conf;
	}
    }
    return NULL;
}

struct gqueue *newqueue() {
    struct gqueue *q;

    q = malloc(sizeof(struct gqueue));
    if (!q)
	debugx(1, DBG_ERR, "malloc failed");
    q->entries = list_create();
    if (!q->entries)
	debugx(1, DBG_ERR, "malloc failed");
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
    return q;
}

void removequeue(struct gqueue *q) {
    struct list_node *entry;

    if (!q)
        return;
    pthread_mutex_lock(&q->mutex);
    for (entry = list_first(q->entries); entry; entry = list_next(entry))
        freerq((struct request *)entry->data);
            list_free(q->entries);
    pthread_cond_destroy(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    free(q);
}

struct client *addclient(struct clsrvconf *conf, uint8_t lock) {
    struct client *new = NULL;

    if (lock)
	pthread_mutex_lock(conf->lock);
    if (!conf->clients) {
	conf->clients = list_create();
	if (!conf->clients) {
	    if (lock)
		pthread_mutex_unlock(conf->lock);
	    debug(DBG_ERR, "malloc failed");
	    return NULL;
	}
    }

    new = calloc(1, sizeof(struct client));
    if (!new) {
        debug(DBG_ERR, "malloc failed");
        if (lock)
            pthread_mutex_unlock(conf->lock);
        return NULL;
    }
    if (!list_push(conf->clients, new)) {
        free(new);
        if (lock)
            pthread_mutex_unlock(conf->lock);
        return NULL;
    }
    new->conf = conf;
    if (conf->pdef->addclient)
	conf->pdef->addclient(new);
    else
    new->replyq = newqueue();
    pthread_mutex_init(&new->lock, NULL);
    if (lock)
	pthread_mutex_unlock(conf->lock);
    return new;
}

void removeclientrqs_sendrq_freeserver_lock(uint8_t wantlock) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    if (wantlock)
	pthread_mutex_lock(&lock);
    else
	pthread_mutex_unlock(&lock);
}

void removeclientrq(struct client *client, int i) {
    struct request *rq;
    struct rqout *rqout;

	rq = client->rqs[i];
	if (!rq)
        return;

    removeclientrqs_sendrq_freeserver_lock(1);
    if (rq->to) {
        rqout = rq->to->requests + rq->newid;
        pthread_mutex_lock(rqout->lock);
        if (rqout->rq == rq) /* still pointing to our request */
            freerqoutdata(rqout);
        pthread_mutex_unlock(rqout->lock);
    }
    client->rqs[i] = NULL;
    freerq(rq);
    removeclientrqs_sendrq_freeserver_lock(0);
}

void removeclientrqs(struct client *client) {
    int i;

    for (i = 0; i < MAX_REQUESTS; i++)
        removeclientrq(client, i);
}

void removelockedclient(struct client *client) {
    struct clsrvconf *conf;

    conf = client->conf;
    if (conf->clients) {
	removeclientrqs(client);
	removequeue(client->replyq);
	list_removedata(conf->clients, client);
    pthread_mutex_destroy(&client->lock);
	free(client->addr);
	free(client);
    }
}

void removeclient(struct client *client) {
    struct clsrvconf *conf;

    if (!client)
	return;

    conf = client->conf;
    pthread_mutex_lock(conf->lock);
    removelockedclient(client);
    pthread_mutex_unlock(conf->lock);
}

void freeserver(struct server *server, uint8_t destroymutex) {
    struct rqout *rqout, *end;

    if (!server)
	return;

    removeclientrqs_sendrq_freeserver_lock(1);
    if (server->requests) {
	rqout = server->requests;
	for (end = rqout + MAX_REQUESTS; rqout < end; rqout++) {
	    freerqoutdata(rqout);
	    pthread_mutex_destroy(rqout->lock);
	    free(rqout->lock);
	}
	free(server->requests);
    }
    free(server->dynamiclookuparg);
    if (server->ssl) {
        SSL_free(server->ssl);
    }
    if (destroymutex) {
	pthread_mutex_destroy(&server->lock);
	pthread_cond_destroy(&server->newrq_cond);
	pthread_mutex_destroy(&server->newrq_mutex);
    }
    removeclientrqs_sendrq_freeserver_lock(0);
    free(server);
}

int addserver(struct clsrvconf *conf) {
    int i;

    if (conf->servers) {
	debug(DBG_ERR, "addserver: currently works with just one server per conf");
	return 0;
    }
    conf->servers = malloc(sizeof(struct server));
    if (!conf->servers) {
	debug(DBG_ERR, "malloc failed");
	return 0;
    }
    memset(conf->servers, 0, sizeof(struct server));
    conf->servers->conf = conf;

    conf->pdef->setsrcres();

    conf->servers->sock = -1;
    if (conf->pdef->addserverextra)
	conf->pdef->addserverextra(conf);

    conf->servers->requests = calloc(MAX_REQUESTS, sizeof(struct rqout));
    if (!conf->servers->requests) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    for (i = 0; i < MAX_REQUESTS; i++) {
	conf->servers->requests[i].lock = malloc(sizeof(pthread_mutex_t));
	if (!conf->servers->requests[i].lock) {
	    debug(DBG_ERR, "malloc failed");
	    goto errexit;
	}
	if (pthread_mutex_init(conf->servers->requests[i].lock, NULL)) {
	    debugerrno(errno, DBG_ERR, "mutex init failed");
	    free(conf->servers->requests[i].lock);
	    conf->servers->requests[i].lock = NULL;
	    goto errexit;
	}
    }
    if (pthread_mutex_init(&conf->servers->lock, NULL)) {
	debugerrno(errno, DBG_ERR, "mutex init failed");
	goto errexit;
    }
    conf->servers->newrq = 0;
    conf->servers->conreset = 0;
    if (pthread_mutex_init(&conf->servers->newrq_mutex, NULL)) {
	debugerrno(errno, DBG_ERR, "mutex init failed");
	pthread_mutex_destroy(&conf->servers->lock);
	goto errexit;
    }
    if (pthread_cond_init(&conf->servers->newrq_cond, NULL)) {
	debugerrno(errno, DBG_ERR, "mutex init failed");
	pthread_mutex_destroy(&conf->servers->newrq_mutex);
	pthread_mutex_destroy(&conf->servers->lock);
	goto errexit;
    }

    return 1;

errexit:
    freeserver(conf->servers, 0);
    conf->servers = NULL;
    return 0;
}

unsigned char *attrget(unsigned char *attrs, int length, uint8_t type) {
    while (length > 1) {
	if (ATTRTYPE(attrs) == type)
	    return attrs;
	length -= ATTRLEN(attrs);
	attrs += ATTRLEN(attrs);
    }
    return NULL;
}

struct request *newrqref(struct request *rq) {
    if (rq) {
        pthread_mutex_lock(&rq->refmutex);
        rq->refcount++;
        pthread_mutex_unlock(&rq->refmutex);
    }
    return rq;
}

void freerq(struct request *rq) {
    if (!rq)
	return;
    pthread_mutex_lock(&rq->refmutex);
    debug(DBG_DBG, "freerq: called with refcount %d", rq->refcount);
    if (--rq->refcount) {
        pthread_mutex_unlock(&rq->refmutex);
        return;
    }
    pthread_mutex_unlock(&rq->refmutex);
    if (rq->origusername)
	free(rq->origusername);
    if (rq->buf)
	free(rq->buf);
    if (rq->replybuf)
	free(rq->replybuf);
    if (rq->msg)
	radmsg_free(rq->msg);
    pthread_mutex_destroy(&rq->refmutex);
    free(rq);
}

void freerqoutdata(struct rqout *rqout) {
    if (!rqout)
	return;
    if (rqout->rq) {
	if (rqout->rq->buf) {
	    free(rqout->rq->buf);
	    rqout->rq->buf = NULL;
	}
	rqout->rq->to = NULL;
	freerq(rqout->rq);
	rqout->rq = NULL;
    }
    rqout->tries = 0;
    memset(&rqout->expiry, 0, sizeof(struct timeval));
}

int _internal_sendrq(struct server *to, uint8_t id, struct request *rq) {
    if (!to->requests[id].rq) {
        pthread_mutex_lock(to->requests[id].lock);
        if (!to->requests[id].rq) {
            rq->newid = id;
            rq->msg->id = id;
            rq->buf = radmsg2buf(rq->msg, to->conf->secret, to->conf->secret_len);
            if (!rq->buf) {
                pthread_mutex_unlock(to->requests[id].lock);
                debug(DBG_ERR, "sendrq: radmsg2buf failed");
                return 0;
            }
            debug(DBG_DBG, "sendrq: inserting packet with id %d in queue for %s", id, to->conf->name);
            to->requests[id].rq = rq;
            pthread_mutex_unlock(to->requests[id].lock);
            return 1;
        }
    }
    pthread_mutex_unlock(to->requests[id].lock);
    return 0;
}

void sendrq(struct request *rq) {
    int i, start;
    struct server *to;

    removeclientrqs_sendrq_freeserver_lock(1);
    to = rq->to;
    if (!to)
        goto errexit;

    start = to->conf->statusserver == RSP_STATSRV_OFF ? 0 : 1;
    pthread_mutex_lock(&to->newrq_mutex);
    if (start && rq->msg->code == RAD_Status_Server) {
        if (!_internal_sendrq(to, 0, rq)) {
            debug(DBG_INFO, "sendrq: status server already in queue, dropping request");
            goto errexit;
        }
    } else {
        if (!to->nextid)
            to->nextid = start;
        /* might simplify if only try nextid, might be ok */
        for (i = to->nextid; i < MAX_REQUESTS; i++) {
            if (_internal_sendrq(to, i, rq))
                break;
        }
        if (i == MAX_REQUESTS) {
            for (i = start; i < to->nextid; i++) {
                if (_internal_sendrq(to, i, rq))
                    break;
            }
            if (i == to->nextid) {
                debug(DBG_WARN, "sendrq: no room in queue for server %s, dropping request", to->conf->name);
                goto errexit;
            }
        }

        if (i >= start) /* i is not reserved for statusserver */
            to->nextid = i + 1;
    }

    if (!to->newrq) {
        to->newrq = 1;
        debug(DBG_DBG, "sendrq: signalling client writer");
        pthread_cond_signal(&to->newrq_cond);
    }

    pthread_mutex_unlock(&to->newrq_mutex);
    removeclientrqs_sendrq_freeserver_lock(0);
    return;

errexit:
    if (rq->from)
        rmclientrq(rq, rq->rqid);
    freerq(rq);
    if (to)
        pthread_mutex_unlock(&to->newrq_mutex);
    removeclientrqs_sendrq_freeserver_lock(0);
}

void sendreply(struct request *rq) {
    uint8_t first;
    struct client *to = rq->from;

    if (!rq->replybuf)
	rq->replybuf = radmsg2buf(rq->msg, to->conf->secret, to->conf->secret_len);
    radmsg_free(rq->msg);
    rq->msg = NULL;
    if (!rq->replybuf) {
	freerq(rq);
	debug(DBG_ERR, "sendreply: radmsg2buf failed");
	return;
    }

    pthread_mutex_lock(&to->replyq->mutex);
    first = list_first(to->replyq->entries) == NULL;

    if (!list_push(to->replyq->entries, rq)) {
	pthread_mutex_unlock(&to->replyq->mutex);
	freerq(rq);
	debug(DBG_ERR, "sendreply: malloc failed");
	return;
    }

    if (first) {
	debug(DBG_DBG, "signalling server writer");
	pthread_cond_signal(&to->replyq->cond);
    }
    pthread_mutex_unlock(&to->replyq->mutex);
}

static int pwdcrypt(char encrypt_flag, uint8_t *in, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt, uint8_t saltlen) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct md5_ctx mdctx;
    unsigned char hash[MD5_DIGEST_SIZE], *input;
    uint8_t i, offset = 0, out[128];

    pthread_mutex_lock(&lock);

    md5_init(&mdctx);
    input = auth;
    for (;;) {
        md5_update(&mdctx, sharedlen, shared);
        md5_update(&mdctx, 16, input);
        if (salt) {
            md5_update(&mdctx, saltlen, salt);
            salt = NULL;
        }
        md5_digest(&mdctx, sizeof(hash), hash);
        for (i = 0; i < 16; i++)
            out[offset + i] = hash[i] ^ in[offset + i];
        if (encrypt_flag)
            input = out + offset;
        else
            input = in + offset;
        offset += 16;
        if (offset == len)
            break;
    }
    memcpy(in, out, len);

    pthread_mutex_unlock(&lock);
    return 1;
}

static int msmppencrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct md5_ctx mdctx;
    unsigned char hash[MD5_DIGEST_SIZE];
    uint8_t i, offset;

    pthread_mutex_lock(&lock);
    md5_init(&mdctx);

#if 0
    printfchars(NULL, "msppencrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppencrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppencrypt in", "%02x ", text, len);
#endif

    md5_update(&mdctx, sharedlen, shared);
    md5_update(&mdctx, 16, auth);
    md5_update(&mdctx, 2, salt);
    md5_digest(&mdctx, sizeof(hash), hash);

#if 0
    printfchars(NULL, "msppencrypt hash", "%02x ", hash, 16);
#endif

    for (i = 0; i < 16; i++)
	text[i] ^= hash[i];

    for (offset = 16; offset < len; offset += 16) {
#if 0
	printf("text + offset - 16 c(%d): ", offset / 16);
	printfchars(NULL, NULL, "%02x ", text + offset - 16, 16);
#endif
        md5_update(&mdctx, sharedlen, shared);
        md5_update(&mdctx, 16, text + offset - 16);
        md5_digest(&mdctx, sizeof(hash), hash);
#if 0
	printfchars(NULL, "msppencrypt hash", "%02x ", hash, 16);
#endif

	for (i = 0; i < 16; i++)
	    text[offset + i] ^= hash[i];
    }

#if 0
    printfchars(NULL, "msppencrypt out", "%02x ", text, len);
#endif

    pthread_mutex_unlock(&lock);
    return 1;
}

static int msmppdecrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct md5_ctx mdctx;
    unsigned char hash[MD5_DIGEST_SIZE];
    uint8_t i, offset;
    char plain[255];

    pthread_mutex_lock(&lock);
    md5_init(&mdctx);

#if 0
    printfchars(NULL, "msppdecrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppdecrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppdecrypt in", "%02x ", text, len);
#endif

    md5_update(&mdctx, sharedlen, shared);
    md5_update(&mdctx, 16, auth);
    md5_update(&mdctx, 2, salt);
    md5_digest(&mdctx, sizeof(hash), hash);

#if 0
    printfchars(NULL, "msppdecrypt hash", "%02x ", hash, 16);
#endif

    for (i = 0; i < 16; i++)
	plain[i] = text[i] ^ hash[i];

    for (offset = 16; offset < len; offset += 16) {
#if 0
	printf("text + offset - 16 c(%d): ", offset / 16);
	printfchars(NULL, NULL, "%02x ", text + offset - 16, 16);
#endif
        md5_update(&mdctx, sharedlen, shared);
        md5_update(&mdctx, 16, text + offset - 16);
        md5_digest(&mdctx, sizeof(hash), hash);
#if 0
	printfchars(NULL, "msppdecrypt hash", "%02x ", hash, 16);
#endif

	for (i = 0; i < 16; i++)
	    plain[offset + i] = text[offset + i] ^ hash[i];
    }

    memcpy(text, plain, len);
#if 0
    printfchars(NULL, "msppdecrypt out", "%02x ", text, len);
#endif

    pthread_mutex_unlock(&lock);
    return 1;
}

struct realm *newrealmref(struct realm *r) {
    if (r) {
        pthread_mutex_lock(&r->refmutex);
	r->refcount++;
        pthread_mutex_unlock(&r->refmutex);
    }
    return r;
}

/* returns with lock on realm */
struct realm *id2realm(struct list *realmlist, char *id) {
    struct list_node *entry;
    struct realm *realm, *subrealm;

    /* need to do locking for subrealms and check subrealm timers */
    for (entry = list_first(realmlist); entry; entry = list_next(entry)) {
	realm = (struct realm *)entry->data;
	if (!regexec(&realm->regex, id, 0, NULL, 0)) {
	    pthread_mutex_lock(&realm->mutex);
	    if (realm->subrealms) {
		subrealm = id2realm(realm->subrealms, id);
		if (subrealm) {
		    pthread_mutex_unlock(&realm->mutex);
		    return subrealm;
		}
	    }
	    return newrealmref(realm);
	}
    }
    return NULL;
}

int hasdynamicserver(struct list *srvconfs) {
    struct list_node *entry;

    for (entry = list_first(srvconfs); entry; entry = list_next(entry))
        if (((struct clsrvconf *)entry->data)->servers->dynamiclookuparg)
	    return 1;
    return 0;
}

/* helper function, only used by removeserversubrealms() */
void _internal_removeserversubrealms(struct list *realmlist, struct clsrvconf *srv) {
    struct list_node *entry, *entry2;
    struct realm *realm;
    struct list *srvconfs;

    for (entry = list_first(realmlist); entry;) {
	realm = newrealmref((struct realm *)entry->data);
    entry = list_next(entry);
	pthread_mutex_lock(&realm->mutex);

	if (realm->srvconfs) {
	    srvconfs = realm->srvconfs;
	    for (entry2 = list_first(realm->srvconfs); entry2; entry2 = list_next(entry2))
		if (entry2->data == srv)
		    freerealm(realm);
	    list_removedata(srvconfs, srv);
	}
	if (realm->accsrvconfs) {
	    srvconfs = realm->accsrvconfs;
	    for (entry2 = list_first(realm->accsrvconfs); entry2; entry2 = list_next(entry2))
		if (entry2->data == srv)
		    freerealm(realm);
	    list_removedata(srvconfs, srv);
	}

	/* remove subrealm if no dynamic servers left */
	if (!hasdynamicserver(realm->srvconfs) && !hasdynamicserver(realm->accsrvconfs)) {
	    while (list_shift(realm->srvconfs))
		freerealm(realm);
	    list_destroy(realm->srvconfs);
	    realm->srvconfs = NULL;
	    while (list_shift(realm->accsrvconfs))
		freerealm(realm);
	    list_destroy(realm->accsrvconfs);
	    realm->accsrvconfs = NULL;
	    list_removedata(realmlist, realm);
	}
	pthread_mutex_unlock(&realm->mutex);
	freerealm(realm);
    }
}

void removeserversubrealms(struct list *realmlist, struct clsrvconf *srv) {
    struct list_node *entry;
    struct realm *realm;

    for (entry = list_first(realmlist); entry; entry = list_next(entry)) {
	realm = (struct realm *)entry->data;
	pthread_mutex_lock(&realm->mutex);
	if (realm->subrealms) {
	    _internal_removeserversubrealms(realm->subrealms, srv);
	    if (!list_first(realm->subrealms)) {
		list_destroy(realm->subrealms);
		realm->subrealms = NULL;
	    }
	}
	pthread_mutex_unlock(&realm->mutex);
    }
}

int pwdrecrypt(uint8_t *pwd, uint8_t len, uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len, uint8_t *oldauth, uint8_t *newauth,
                uint8_t *oldsalt, uint8_t oldsaltlen, uint8_t *newsalt, uint8_t newsaltlen) {
    if (len < 16 || len > 128 || len % 16) {
	debug(DBG_WARN, "pwdrecrypt: invalid password length");
	return 0;
    }

    if (!pwdcrypt(0, pwd, len, oldsecret, oldsecret_len, oldauth, oldsalt, oldsaltlen)) {
	debug(DBG_WARN, "pwdrecrypt: cannot decrypt password");
	return 0;
    }
#ifdef DEBUG
    printfchars(NULL, "pwdrecrypt: password", "%02x ", pwd, len);
#endif
    if (!pwdcrypt(1, pwd, len, newsecret, newsecret_len, newauth, newsalt, newsaltlen)) {
	debug(DBG_WARN, "pwdrecrypt: cannot encrypt password");
	return 0;
    }
    return 1;
}

int msmpprecrypt(uint8_t *msmpp, uint8_t len, uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len, uint8_t *oldauth, uint8_t *newauth) {
    if (len < 18)
	return 0;
    if (!msmppdecrypt(msmpp + 2, len - 2, oldsecret, oldsecret_len, oldauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to decrypt msppe key");
	return 0;
    }
    if (!msmppencrypt(msmpp + 2, len - 2, newsecret, newsecret_len, newauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to encrypt msppe key");
	return 0;
    }
    return 1;
}

int msmppe(unsigned char *attrs, int length, uint8_t type, char *attrtxt, struct request *rq,
	   uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len) {
    unsigned char *attr;

    for (attr = attrs; (attr = attrget(attr, length - (attr - attrs), type)); attr += ATTRLEN(attr)) {
	debug(DBG_DBG, "msmppe: Got %s", attrtxt);
	if (!msmpprecrypt(ATTRVAL(attr), ATTRVALLEN(attr), oldsecret, oldsecret_len, newsecret, newsecret_len, rq->buf + 4, rq->rqauth))
	    return 0;
    }
    return 1;
}

int rewriteusername(struct request *rq, struct tlv *attr) {
    char *orig = (char *)tlv2str(attr);
    if (!dorewritemodattr(attr, rq->from->conf->rewriteusername)) {
	free(orig);
	return 0;
    }
    if (strlen(orig) != attr->l || memcmp(orig, attr->v, attr->l))
	rq->origusername = (char *)orig;
    else
	free(orig);
    return 1;
}

void addttlattr(struct radmsg *msg, uint32_t *attrtype, uint8_t addttl) {
    uint8_t ttl[4];
    struct tlv *attr;

    memset(ttl, 0, 4);
    ttl[3] = addttl;

    if (attrtype[1] == 256) { /* not vendor */
	attr = maketlv(attrtype[0], 4, ttl);
	if (attr && !radmsg_add(msg, attr))
	    freetlv(attr);
    } else {
	attr = maketlv(attrtype[1], 4, ttl);
	if (attr)
	    addvendorattr(msg, attrtype[0], attr);
    }
}

int decttl(uint8_t l, uint8_t *v) {
    int i;

    if (l == 0)
	return 0;

    i = l - 1;
    if (v[i]) {
	if (--v[i--])
	    return 1;
	while (i >= 0 && !v[i])
	    i--;
	return i >= 0;
    }
    for (i--; i >= 0 && !v[i]; i--);
    if (i < 0)
	return 0;
    v[i]--;
    while (++i < l)
	v[i] = 255;
    return 1;
}

/* returns -1 if no ttl, 0 if exceeded, 1 if ok */
int checkttl(struct radmsg *msg, uint32_t *attrtype) {
    uint8_t alen, *subattrs;
    struct tlv *attr;
    struct list_node *node;
    uint32_t vendor;
    int sublen;

    if (attrtype[1] == 256) { /* not vendor */
	attr = radmsg_gettype(msg, attrtype[0]);
	if (attr)
	    return decttl(attr->l, attr->v);
    } else
	for (node = list_first(msg->attrs); node; node = list_next(node)) {
	    attr = (struct tlv *)node->data;
	    if (attr->t != RAD_Attr_Vendor_Specific || attr->l <= 4)
		continue;
	    memcpy(&vendor, attr->v, 4);
	    if (ntohl(vendor) != attrtype[0])
		continue;
	    sublen = attr->l - 4;
	    subattrs = attr->v + 4;
	    if (!attrvalidate(subattrs, sublen))
		continue;
	    while (sublen > 1) {
		if (ATTRTYPE(subattrs) == attrtype[1])
		    return decttl(ATTRVALLEN(subattrs), ATTRVAL(subattrs));
		alen = ATTRLEN(subattrs);
		sublen -= alen;
		subattrs += alen;
	    }
	}
    return -1;
}

const char *radmsgtype2string(uint8_t code) {
    static const char *rad_msg_names[] = {
	"", "Access-Request", "Access-Accept", "Access-Reject",
	"Accounting-Request", "Accounting-Response", "", "",
	"", "", "", "Access-Challenge",
	"Status-Server", "Status-Client"
    };
    static const char *rad_dynauth_msg_names[] = {
        "Disconnect-Request", "Disconnect-ACK", "Disconnect-NAK", "CoA-Request",
        "CoA-ACK", "CoA-NAK"
    };
    if (code >= 40 && code <= 45) {
        return *rad_dynauth_msg_names[code - 40] ? rad_dynauth_msg_names[code - 40] : "Unknown";
    }
    return code < 14 && *rad_msg_names[code] ? rad_msg_names[code] : "Unknown";
}

void char2hex(char *h, unsigned char c) {
    static const char hexdigits[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    h[0] = hexdigits[c / 16];
    h[1] = hexdigits[c % 16];
    return;
}

uint8_t *radattr2ascii(struct tlv *attr) {
    int i, l;
    uint8_t *a, *d;

    if (!attr)
	return NULL;

    l = attr->l;
    for (i = 0; i < attr->l; i++)
	if (attr->v[i] < 32 || attr->v[i] > 126)
	    l += 2;
    if (l == attr->l)
	return (uint8_t *)stringcopy((char *)attr->v, attr->l);

    a = malloc(l + 1);
    if (!a)
	return NULL;

    d = a;
    for (i = 0; i < attr->l; i++)
	if (attr->v[i] < 32 || attr->v[i] > 126) {
	    *d++ = '%';
	    char2hex((char *)d, attr->v[i]);
	    d += 2;
	} else
	    *d++ = attr->v[i];
    *d = '\0';
    return a;
}

void replylog(struct radmsg *msg, struct server *server, struct request *rq) {
    uint8_t *username, *logusername = NULL, *stationid, *replymsg, *tmpmsg;
    char *servername, *logstationid = NULL;
    uint8_t level = DBG_NOTICE;
    char tmp[INET6_ADDRSTRLEN];

    servername = server ? server->conf->name : "_self_";
    username = radattr2ascii(radmsg_gettype(rq->msg, RAD_Attr_User_Name));
    if (username) {
        logusername = options.logfullusername ? username : (uint8_t *)strchr((char *)username, '@');
    }
    stationid = radattr2ascii(radmsg_gettype(rq->msg, RAD_Attr_Calling_Station_Id));
    if (stationid) {
        logstationid = calloc(128, sizeof(char));
        sprintf((char *)logstationid, " stationid ");
        switch (options.log_mac) {
            case RSP_MAC_VENDOR_HASHED:
            case RSP_MAC_VENDOR_KEY_HASHED:
                memcpy(logstationid + 11, stationid, 9);
                fticks_hashmac((uint8_t *)stationid, options.log_mac == RSP_MAC_VENDOR_KEY_HASHED ?
                    options.log_key : NULL, 65, (uint8_t *)logstationid+20);
                break;
            case RSP_MAC_FULLY_HASHED:
            case RSP_MAC_FULLY_KEY_HASHED:
                fticks_hashmac((uint8_t *)stationid, options.log_mac == RSP_MAC_FULLY_KEY_HASHED ?
                    options.log_key : NULL, 65, (uint8_t *)logstationid+11);
                break;
            case RSP_MAC_STATIC:
                sprintf(logstationid+11, "undisclosed");
                break;
            case RSP_MAC_ORIGINAL:
            default:
                strncpy(logstationid+11, (char *)stationid, 128-12);
        }
        free(stationid);
    }
    replymsg = radattr2ascii(radmsg_gettype(msg, RAD_Attr_Reply_Message));
    if (replymsg) {
        if (asprintf((char **)&tmpmsg, " (%s)", replymsg) >= 0) {
            free(replymsg);
            replymsg = tmpmsg;
        }
    }

    if (msg->code == RAD_Access_Accept || msg->code == RAD_Access_Reject || msg->code == RAD_Accounting_Response) {
        if (msg->code == RAD_Accounting_Response)
            level = DBG_INFO;
        if (logusername) {
            debug(level, "%s for user %s%s from %s%s to %s (%s)",
                radmsgtype2string(msg->code), logusername, logstationid ? logstationid : "",
                servername, replymsg ? (char *)replymsg : "", rq->from->conf->name,
                addr2string(rq->from->addr, tmp, sizeof(tmp)));
        } else {
            debug(level, "%s (response to %s) from %s to %s (%s)", radmsgtype2string(msg->code),
                radmsgtype2string(rq->msg->code), servername,
                rq->from->conf->name, addr2string(rq->from->addr, tmp, sizeof(tmp)));
        }
    } else if(msg->code == RAD_Access_Request) {
        debug(level, "missing response to %s for user %s%s from %s (%s) to %s",
            radmsgtype2string(msg->code), logusername, logstationid ? logstationid : "",
            rq->from->conf->name, addr2string(rq->from->addr, tmp, sizeof(tmp)), servername);
    }
    free(username);
    free(logstationid);
    free(replymsg);
}

void respond(struct request *rq, uint8_t code, char *message,
             int copy_proxystate_flag, int add_msg_auth, int err_cause)
{
    struct radmsg *msg;
    struct tlv *attr;
    char tmp[INET6_ADDRSTRLEN];
    uint32_t err;

    msg = radmsg_init(code, rq->msg->id, rq->msg->auth);
    if (!msg) {
        debug(DBG_ERR, "respond: malloc failed");
        return;
    }

    if (add_msg_auth) {
        attr = maketlv(RAD_Attr_Message_Authenticator, 16, NULL);
        if (!attr || !radmsg_add(msg, attr)) {
            freetlv(attr);
            radmsg_free(msg);
            debug(DBG_ERR, "respond: malloc failed");
            return;
        }
    }
    if (message && *message) {
        attr = maketlv(RAD_Attr_Reply_Message, strlen(message), message);
        if (!attr || !radmsg_add(msg, attr)) {
            freetlv(attr);
            radmsg_free(msg);
            debug(DBG_ERR, "respond: malloc failed");
            return;
        }
    }
    if (copy_proxystate_flag) {
        if (radmsg_copy_attrs(msg, rq->msg, RAD_Attr_Proxy_State) < 0) {
            debug(DBG_ERR, "%s: unable to copy all Proxy-State attributes",
                  __func__);
        }
    }
    if (err_cause > 0) {
        /*
         * Error_Cause attr value should be 4 bytes long. We ensure here that the
         * 4 byte value is stored in network byte order in memory i.e
         * most significant byte first. This is because we don't convert each
         * individual attr value to network byte order while sending replybuf to wire.
         */
        err = htonl(err_cause);
        attr = maketlv(RAD_Attr_Error_Cause, 4, &err);
        if (!attr || !radmsg_add(msg, attr)) {
            freetlv(attr);
            radmsg_free(msg);
            debug(DBG_ERR, "respond: malloc failed");
            return;
        }
    }

    replylog(msg, NULL, rq);
    debug(DBG_DBG, "respond: sending %s (id %d) to %s (%s)", radmsgtype2string(msg->code), msg->id, rq->from->conf->name, addr2string(rq->from->addr, tmp, sizeof(tmp)));

    radmsg_free(rq->msg);
    rq->msg = msg;
    sendreply(newrqref(rq));
}

struct clsrvconf *choosesrvconf(struct list *srvconfs) {
    struct list_node *entry;
    struct clsrvconf *server, *best = NULL, *first = NULL;

    for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
        server = (struct clsrvconf *)entry->data;
        if (!server->servers)
            return server;
        if (server->servers->state == RSP_SERVER_STATE_FAILING)
            continue;
        if (!first)
            first = server;
        if (server->servers->state == RSP_SERVER_STATE_STARTUP || server->servers->state == RSP_SERVER_STATE_RECONNECTING)
            continue;
        if (!server->servers->lostrqs)
            return server;
        if (!best) {
            best = server;
            continue;
        }
        if (server->servers->lostrqs < best->servers->lostrqs)
            best = server;
    }
    if (best && best->servers->lostrqs == MAX_LOSTRQS)
        for (entry = list_first(srvconfs); entry; entry = list_next(entry))
            if (((struct clsrvconf *)entry->data)->servers->lostrqs == MAX_LOSTRQS)
                ((struct clsrvconf *)entry->data)->servers->lostrqs--;
    return best ? best : first;
}

struct list *getsrvconfs(struct realm *realm, uint8_t acc, uint8_t coa) {
    if (coa) {
        return realm->dynauthsrvconfs;
    } else if (acc) {
        return realm->accsrvconfs;
    } else {
        return realm->srvconfs;
    }
}

/*
 * find an appropriate server to send requests to based on the given realm name
 * 
 * @params
 *     - realm : pointer to realm object to fill
 *     - id : string representing the realm name to match
 *     - acc : whether to return an accountingServer configured for the realm
 *     - coa : whether to return a dynAuthServer configured for the realm 
 * 
 * returns with lock on realm, protects from server changes while in use by
 * radsrv/sendrq
 */
struct server *findserver(struct realm **realm, char *id, uint8_t acc, uint8_t coa) {
    struct clsrvconf *srvconf;
    struct realm *subrealm;
    struct server *server = NULL;

    if (!id)
	return NULL;
    /* returns with lock on realm */
    *realm = id2realm(realms, id);
    if (!*realm)
	goto exit;
    debug(DBG_DBG, "found matching realm: %s", (*realm)->name);
    srvconf = choosesrvconf(getsrvconfs(*realm, acc, coa));
    if (srvconf && !(*realm)->parent && !srvconf->servers && srvconf->dynamiclookupcommand) {
	subrealm = adddynamicrealmserver(*realm, id);
	if (subrealm) {
	    pthread_mutex_lock(&subrealm->mutex);
	    pthread_mutex_unlock(&(*realm)->mutex);
	    freerealm(*realm);
	    *realm = subrealm;
            debug(DBG_DBG, "added realm: %s", (*realm)->name);
	    srvconf = choosesrvconf(getsrvconfs(*realm, acc, coa));
            debug(DBG_DBG, "found conf for new realm: %s", srvconf->name);
	}
    }
    if (srvconf) {
        debug(DBG_DBG, "found matching conf: %s", srvconf->name);
	server = srvconf->servers;
    }

exit:
    return server;
}


struct request *newrequest() {
    struct request *rq;

    rq = malloc(sizeof(struct request));
    if (!rq) {
	debug(DBG_ERR, "newrequest: malloc failed");
	return NULL;
    }
    memset(rq, 0, sizeof(struct request));
    rq->refcount = 1;
    pthread_mutex_init(&rq->refmutex, NULL);
    gettimeofday(&rq->created, NULL);
    return rq;
}

static void
purgedupcache(struct client *client) {
    struct request *r;
    struct timeval now;
    int i;

    gettimeofday(&now, NULL);
    for (i = 0; i < MAX_REQUESTS; i++) {
	r = client->rqs[i];
	if (r && now.tv_sec - r->created.tv_sec > r->from->conf->dupinterval) {
        removeclientrq(client, i);
	}
    }
}

int addclientrq(struct request *rq) {
    struct request *r;
    struct timeval now;
    char tmp[INET6_ADDRSTRLEN];

    r = rq->from->rqs[rq->rqid];
    if (r) {
	if (!memcmp(rq->rqauth, r->rqauth, 16)) {
	    gettimeofday(&now, NULL);
	    if (now.tv_sec - r->created.tv_sec < r->from->conf->dupinterval) {
		if (r->replybuf) {
		    debug(DBG_INFO, "addclientrq: already sent reply to request with id %d from %s, resending", rq->rqid, addr2string(r->from->addr, tmp, sizeof(tmp)));
		    sendreply(newrqref(r));
		} else
		    debug(DBG_INFO, "addclientrq: already got request with id %d from %s, ignoring", rq->rqid, addr2string(r->from->addr, tmp, sizeof(tmp)));
		return 0;
	    }
	}
    removeclientrq(rq->from, rq->rqid);
    }
    rq->from->rqs[rq->rqid] = newrqref(rq);
    return 1;
}

void rmclientrq(struct request *rq, uint8_t id) {
    struct request *r;

    r = rq->from->rqs[id];
    if (r) {
	freerq(r);
	rq->from->rqs[id] = NULL;
    }
}

/* Called from server readers, handling incoming requests from
 * clients. */
/* returns 0 if validation/authentication fails, else 1 */
int radsrv(struct request *rq) {
    struct radmsg *msg = NULL;
    struct tlv *attr;
    uint8_t *userascii = NULL;
    struct realm *realm = NULL;
    struct server *to = NULL;
    struct client *from = rq->from;
    int ttlres;
    char tmp[INET6_ADDRSTRLEN];
    char *realmname = NULL;

    msg = buf2radmsg(rq->buf, from->conf->secret, from->conf->secret_len, NULL);
    free(rq->buf);
    rq->buf = NULL;

    if (!msg) {
	debug(DBG_NOTICE, "radsrv: ignoring request from %s (%s), validation failed.", from->conf->name, addr2string(from->addr, tmp, sizeof(tmp)));
	freerq(rq);
	return 0;
    }

    rq->msg = msg;
    rq->rqid = msg->id;
    memcpy(rq->rqauth, msg->auth, 16);

    debug(DBG_DBG, "radsrv: code %d, id %d", msg->code, msg->id);
    if (msg->code != RAD_Access_Request && msg->code != RAD_Status_Server && msg->code != RAD_Accounting_Request && !DYNAUTH_REQ(msg->code)) {
	debug(DBG_INFO, "radsrv: server currently accepts only access-requests, accounting-requests, status-server, disconnect and CoA requests, ignoring");
	goto exit;
    }

    purgedupcache(from);
    if (!addclientrq(rq))
	goto exit;

    if (msg->code == RAD_Status_Server) {
	respond(rq, RAD_Access_Accept, NULL, 1, 0, 0);
	goto exit;
    }

    /*
     * below: code == RAD_Access_Request || code == RAD_Accounting_Request
     *        || code == RAD_CoA_Request || code == RAD_Disconnect_Request
     */

    if (from->conf->rewritein && !dorewrite(msg, from->conf->rewritein))
	goto rmclrqexit;

    ttlres = checkttl(msg, options.ttlattrtype);
    if (!ttlres) {
	debug(DBG_INFO, "radsrv: ignoring request from client %s (%s), ttl exceeded", from->conf->name, addr2string(from->addr, tmp, sizeof(tmp)));
	goto exit;
    }

    if (msg->code == RAD_Access_Request || msg->code == RAD_Accounting_Request) {
        attr = radmsg_gettype(msg, RAD_Attr_User_Name);
        if (!attr) {
            if (msg->code == RAD_Accounting_Request) {
                respond(rq, RAD_Accounting_Response, NULL, 1, 0, 0);
            } else
                debug(DBG_INFO, "radsrv: ignoring access request, no username attribute");
            goto exit;
        }

        if (from->conf->rewriteusername && !rewriteusername(rq, attr)) {
            debug(DBG_WARN, "radsrv: username malloc failed, ignoring request");
            goto rmclrqexit;
        }
    } else if (DYNAUTH_REQ(msg->code)) {
        attr = radmsg_gettype(msg, RAD_Attr_Operator_Name);
        if (!attr) {
            debug(DBG_INFO,
                  "radsrv: no operatorname attribute in dynauth reqeust, sending NAK");
            if (msg->code == RAD_Disconnect_Request) {
                respond(rq, RAD_Disconnect_NAK, NULL, 1, 0, RAD_Err_Request_Not_Routable);
            } else if (msg->code == RAD_CoA_Request) {
                respond(rq, RAD_CoA_NAK, NULL, 1, 0, RAD_Err_Request_Not_Routable);
            }
            goto exit;
        }
    } else {
        goto exit;
    }

    userascii = radattr2ascii(attr);
    if (!userascii)
        goto rmclrqexit;
    debug(DBG_INFO, "radsrv: got %s (id %d) with %s: %s from client %s (%s)",
          radmsgtype2string(msg->code), msg->id,
          DYNAUTH_REQ(msg->code) ? "operatorname" : "username", userascii,
          from->conf->name, addr2string(from->addr, tmp, sizeof(tmp)));
    
    realmname = (char *)tlv2str(attr);
    /*
     * first char of Operator-Name attr is an ASCII encoded '1' followed by actual
     * realmname
     */
    if (DYNAUTH_REQ(msg->code)) {
        if (!realmname || realmname[0] != '1') {
            debug(DBG_INFO,
                  "radsrv: invalid operatorname attribute in dynauth request, sending NAK");
            if (msg->code == RAD_Disconnect_Request) {
                respond(rq, RAD_Disconnect_NAK, NULL, 1, 0, RAD_Err_Request_Not_Routable);
            } else if (msg->code == RAD_CoA_Request) {
                respond(rq, RAD_CoA_NAK, NULL, 1, 0, RAD_Err_Request_Not_Routable);
            }
            goto exit;
        }
        /*
         * strip ascii '1' from the start of operatorname and replace it with '@'
         * because the constructed regex for configured realms expects an '@' in the string
         */
        realmname[0] = '@';
    }
    
    /* will return with lock on the realm */
    to = findserver(&realm, realmname, msg->code == RAD_Accounting_Request,
                    DYNAUTH_REQ(msg->code));
    if (!realm) {
        if (msg->code == RAD_Access_Request || msg->code == RAD_Accounting_Request) {
            debug(DBG_INFO, "radsrv: ignoring request, don't know where to send it");
        } else if (DYNAUTH_REQ(msg->code)) {
            debug(DBG_INFO, "radsrv: unknown realm, sending NAK");
            /* 
             * If realm is unknown, send a NAK with Error-Cause attribute having
             * value 502 = "Request not Routable"
             */
            if (msg->code == RAD_Disconnect_Request) {
                respond(rq, RAD_Disconnect_NAK, NULL, 1, 0, RAD_Err_Request_Not_Routable);
            } else if (msg->code == RAD_CoA_Request) {
                respond(rq, RAD_CoA_NAK, NULL, 1, 0, RAD_Err_Request_Not_Routable);
            }
        }
        goto exit;
    }

    if (!to) {
        if (realm->message && msg->code == RAD_Access_Request) {
            debug(DBG_INFO, "radsrv: sending %s (id %d) to %s (%s) for %s", radmsgtype2string(RAD_Access_Reject), msg->id, from->conf->name, addr2string(from->addr, tmp, sizeof(tmp)), userascii);
            respond(rq, RAD_Access_Reject, realm->message, 1, 1, 0);
        } else if (realm->accresp && msg->code == RAD_Accounting_Request) {
            respond(rq, RAD_Accounting_Response, NULL, 1, 0, 0);
        } else if (DYNAUTH_REQ(msg->code)) {
            if (msg->code == RAD_Disconnect_Request) {
                respond(rq, RAD_Disconnect_NAK, NULL, 1, 0, 0);
            } else if (msg->code == RAD_CoA_Request) {
                respond(rq, RAD_CoA_NAK, NULL, 1, 0, 0);
            }
        }
        goto exit;
    }

    if ((to->conf->loopprevention == 1
	 || (to->conf->loopprevention == UCHAR_MAX && options.loopprevention == 1))
	&& !strcmp(from->conf->name, to->conf->name)) {
	debug(DBG_INFO, "radsrv: Loop prevented, not forwarding request from client %s (%s) to server %s, discarding",
	      from->conf->name, addr2string(from->addr, tmp, sizeof(tmp)), to->conf->name);
	goto exit;
    }

    /* If there is a CHAP-Password attribute but no CHAP-Challenge
     * one, create a CHAP-Challenge containing the Request
     * Authenticator because that's what the CHAP-Password is based
     * on. */
    attr = radmsg_gettype(msg, RAD_Attr_CHAP_Password);
    if (attr) {
	debug(DBG_DBG, "%s: found CHAP-Password with value length %d", __func__,
              attr->l);
        attr = radmsg_gettype(msg, RAD_Attr_CHAP_Challenge);
        if (attr == NULL) {
            debug(DBG_DBG, "%s: no CHAP-Challenge found, creating one", __func__);
            attr = maketlv(RAD_Attr_CHAP_Challenge, 16, msg->auth);
            if (attr == NULL || radmsg_add(msg, attr) != 1) {
                debug(DBG_ERR, "%s: adding CHAP-Challenge failed, "
                      "CHAP-Password request dropped", __func__);
                freetlv(attr);
                goto rmclrqexit;
            }
        }
    }

    /*
     * Create new Request Authenticator.
     * For Accounting and dynamic authorization requests, authenticator is 16 bytes of zero
     */
    if (msg->code == RAD_Accounting_Request || DYNAUTH_REQ(msg->code))
	memset(msg->auth, 0, 16);
    else if (!RAND_bytes(msg->auth, 16)) {
	debug(DBG_WARN, "radsrv: failed to generate random auth");
	goto rmclrqexit;
    }

#ifdef DEBUG
    printfchars(NULL, "auth", "%02x ", msg->auth, 16);
#endif

    attr = radmsg_gettype(msg, RAD_Attr_User_Password);
    if (attr) {
        debug(DBG_DBG, "radsrv: found userpwdattr with value length %d", attr->l);
        if (!pwdrecrypt(attr->v, attr->l, from->conf->secret, from->conf->secret_len, to->conf->secret, to->conf->secret_len, rq->rqauth, msg->auth, NULL, 0, NULL, 0))
            goto rmclrqexit;
    }

    if (to->conf->rewriteout && !dorewrite(msg, to->conf->rewriteout))
	goto rmclrqexit;

    if (ttlres == -1 && (options.addttl || to->conf->addttl))
	addttlattr(msg, options.ttlattrtype, to->conf->addttl ? to->conf->addttl : options.addttl);

    free(userascii);
    free(realmname);
    rq->to = to;
    sendrq(rq);
    pthread_mutex_unlock(&realm->mutex);
    freerealm(realm);
    return 1;

rmclrqexit:
    rmclientrq(rq, msg->id);
exit:
    freerq(rq);
    free(userascii);
    free(realmname);
    if (realm) {
	pthread_mutex_unlock(&realm->mutex);
	freerealm(realm);
    }
    return 1;
}

/* Called from client readers, handling replies from servers. */
void replyh(struct server *server, unsigned char *buf) {
    struct client *from;
    struct rqout *rqout;
    int sublen, ttlres;
    unsigned char *subattrs;
    struct radmsg *msg = NULL;
    struct tlv *attr;
    struct list_node *node;
    char tmp[INET6_ADDRSTRLEN];

    server->lostrqs = 0;

    rqout = server->requests + buf[1];
    pthread_mutex_lock(rqout->lock);
    if (!rqout->tries) {
	free(buf);
	buf = NULL;
	debug(DBG_INFO, "replyh: no outstanding request with this id, ignoring reply");
	goto errunlock;
    }

    msg = buf2radmsg(buf, server->conf->secret, server->conf->secret_len, rqout->rq->msg->auth);
#ifdef DEBUG
    printfchars(NULL, "origauth/buf+4", "%02x ", buf + 4, 16);
#endif
    free(buf);
    buf = NULL;
    if (!msg) {
        debug(DBG_NOTICE, "replyh: ignoring message from server %s, validation failed", server->conf->name);
	goto errunlock;
    }
    if (msg->code != RAD_Access_Accept && msg->code != RAD_Access_Reject && msg->code != RAD_Access_Challenge
	&& msg->code != RAD_Accounting_Response && !DYNAUTH_RES(msg->code)) {
	debug(DBG_INFO, "replyh: discarding message type %s, accepting only access accept, access reject, access challenge, accounting response, disconnect ack, disconnect nak, coa ack and coa nak messages", radmsgtype2string(msg->code));
	goto errunlock;
    }
    debug(DBG_DBG, "got %s message with id %d", radmsgtype2string(msg->code), msg->id);

    gettimeofday(&server->lastrcv, NULL);

    if (rqout->rq->msg->code == RAD_Status_Server) {
        freerqoutdata(rqout);
        debug(DBG_NOTICE, "replyh: got status server response from %s", server->conf->name);
        if (server->conf->statusserver == RSP_STATSRV_AUTO)
            server->conf->statusserver = RSP_STATSRV_MINIMAL;
        goto errunlock;
    }

    gettimeofday(&server->lastreply, NULL);

    if (server->conf->rewritein && !dorewrite(msg, server->conf->rewritein)) {
	debug(DBG_INFO, "replyh: rewritein failed");
	goto errunlock;
    }

    ttlres = checkttl(msg, options.ttlattrtype);
    if (!ttlres) {
	debug(DBG_INFO, "replyh: ignoring reply from server %s, ttl exceeded", server->conf->name);
	goto errunlock;
    }

    from = rqout->rq->from;

    /* MS MPPE */
    for (node = list_first(msg->attrs); node; node = list_next(node)) {
	attr = (struct tlv *)node->data;
	if (attr->t != RAD_Attr_Vendor_Specific)
	    continue;
	if (attr->l <= 4)
	    break;
	if (attr->v[0] != 0 || attr->v[1] != 0 || attr->v[2] != 1 || attr->v[3] != 55)  /* 311 == MS */
	    continue;

	sublen = attr->l - 4;
	subattrs = attr->v + 4;
	if (!attrvalidate(subattrs, sublen) ||
	    !msmppe(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Send_Key, "MS MPPE Send Key",
		    rqout->rq, server->conf->secret, server->conf->secret_len, from->conf->secret, from->conf->secret_len) ||
	    !msmppe(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Recv_Key, "MS MPPE Recv Key",
		    rqout->rq, server->conf->secret, server->conf->secret_len, from->conf->secret, from->conf->secret_len))
	    break;
    }
    if (node) {
	debug(DBG_WARN, "replyh: MS attribute handling failed, ignoring reply");
	goto errunlock;
    }

    /* reencrypt tunnel-password RFC2868 */
    attr = radmsg_gettype(msg, RAD_Attr_Tunnel_Password);
    if (attr && msg->code == RAD_Access_Accept) {
        uint8_t newsalt[2];
        debug(DBG_DBG, "replyh: found tunnelpwdattr with value length %d", attr->l);
        if (!RAND_bytes(newsalt,2))
            goto errunlock;
        newsalt[0] |= 0x80;
        if (!pwdrecrypt(attr->v+3, attr->l-3, server->conf->secret, server->conf->secret_len, from->conf->secret, from->conf->secret_len,
                        rqout->rq->msg->auth, rqout->rq->rqauth, attr->v+1, 2, newsalt, 2))
            goto errunlock;
        memcpy(attr->v+1, newsalt, 2);
    }

    replylog(msg, server, rqout->rq);

    if (msg->code == RAD_Access_Accept || msg->code == RAD_Access_Reject)
    if (options.fticks_reporting && from->conf->fticks_viscountry != NULL)
        fticks_log(&options, from, msg, rqout->rq);

    msg->id = (char)rqout->rq->rqid;
    memcpy(msg->auth, rqout->rq->rqauth, 16);

    if (rqout->rq->origusername && (attr = radmsg_gettype(msg, RAD_Attr_User_Name))) {
	if (!resizeattr(attr, strlen(rqout->rq->origusername))) {
	    debug(DBG_WARN, "replyh: malloc failed, ignoring reply");
	    goto errunlock;
	}
	memcpy(attr->v, rqout->rq->origusername, strlen(rqout->rq->origusername));
    }

    if (from->conf->rewriteout && !dorewrite(msg, from->conf->rewriteout)) {
	debug(DBG_WARN, "replyh: rewriteout failed");
	goto errunlock;
    }

    if (ttlres == -1 && (options.addttl || from->conf->addttl))
	addttlattr(msg, options.ttlattrtype, from->conf->addttl ? from->conf->addttl : options.addttl);

    debug(DBG_DBG, "replyh: passing %s (id %d) to client %s (%s)", radmsgtype2string(msg->code), msg->id, from->conf->name, addr2string(from->addr, tmp, sizeof(tmp)));

    radmsg_free(rqout->rq->msg);
    rqout->rq->msg = msg;
    sendreply(newrqref(rqout->rq));
    freerqoutdata(rqout);
    pthread_mutex_unlock(rqout->lock);
    return;

errunlock:
    radmsg_free(msg);
    pthread_mutex_unlock(rqout->lock);
    return;
}

struct request *createstatsrvrq() {
    struct request *rq;
    struct tlv *attr;

    rq = newrequest();
    if (!rq)
	return NULL;
    rq->msg = radmsg_init(RAD_Status_Server, 0, NULL);
    if (!rq->msg)
	goto exit;
    attr = maketlv(RAD_Attr_Message_Authenticator, 16, NULL);
    if (!attr)
	goto exit;
    if (!radmsg_add(rq->msg, attr)) {
	freetlv(attr);
	goto exit;
    }
    return rq;

exit:
    freerq(rq);
    return NULL;
}

/* code for removing state not finished */
void *clientwr(void *arg) {
    struct server *server = (struct server *)arg;
    struct rqout *rqout = NULL;
    pthread_t clientrdth;
    int i, dynconffail = 0;
    time_t secs;
    uint8_t rnd, do_resend = 0, statusserver_requested = 0;
    struct timeval now, laststatsrv;
    struct timespec timeout;
    struct request *statsrvrq;
    struct clsrvconf *conf;

    assert(server);
    conf = server->conf;

#define ZZZ 900

    server->state = RSP_SERVER_STATE_STARTUP;
    if (server->dynamiclookuparg && !dynamicconfig(server)) {
	dynconffail = 1;
	server->state = RSP_SERVER_STATE_FAILING;
	debug(DBG_WARN, "%s: dynamicconfig(%s: %s) failed, sleeping %ds",
              __func__, server->conf->name, server->dynamiclookuparg, ZZZ);
	sleep(ZZZ);
	goto errexit;
    }
    /* FIXME: Is resolving not always done by compileserverconfig(),
     * either as part of static configuration setup or by
     * dynamicconfig() above?  */
    if (!resolvehostports(conf->hostports, conf->hostaf, conf->pdef->socktype)) {
        debug(DBG_WARN, "%s: resolve failed, sleeping %ds", __func__, ZZZ);
	server->state = RSP_SERVER_STATE_FAILING;
        sleep(ZZZ);
        goto errexit;
    }

    memset(&timeout, 0, sizeof(struct timespec));

    gettimeofday(&server->lastreply, NULL);
    server->lastrcv = server->lastreply;
    laststatsrv = server->lastreply;

    if (conf->pdef->connecter) {
	if (!conf->pdef->connecter(server, server->dynamiclookuparg ? 5 : 0, "clientwr")) {
	    server->state = RSP_SERVER_STATE_FAILING;
	    if (server->dynamiclookuparg) {
                debug(DBG_WARN, "%s: connect failed, sleeping %ds",
                      __func__, ZZZ);
		sleep(ZZZ);
	    }
	    goto errexit;
	}
	if (pthread_create(&clientrdth, &pthread_attr, conf->pdef->clientconnreader, (void *)server)) {
	    debugerrno(errno, DBG_ERR, "clientwr: pthread_create failed");
	    server->state = RSP_SERVER_STATE_FAILING;
	    goto errexit;
	}
    }
    server->state = RSP_SERVER_STATE_CONNECTED;

    for (;;) {
	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->newrq) {
	    gettimeofday(&now, NULL);
	    /* random 0-7 seconds */
	    RAND_bytes(&rnd, 1);
	    rnd /= 32;
	    if (conf->statusserver != RSP_STATSRV_OFF) {
		secs = server->lastrcv.tv_sec > laststatsrv.tv_sec ? server->lastrcv.tv_sec : laststatsrv.tv_sec;
		if (now.tv_sec - secs > STATUS_SERVER_PERIOD)
		    secs = now.tv_sec;
		if (!timeout.tv_sec || timeout.tv_sec > secs + STATUS_SERVER_PERIOD + rnd)
		    timeout.tv_sec = secs + STATUS_SERVER_PERIOD + rnd;
	    } else {
		if (!timeout.tv_sec || timeout.tv_sec > now.tv_sec + STATUS_SERVER_PERIOD + rnd)
		    timeout.tv_sec = now.tv_sec + STATUS_SERVER_PERIOD + rnd;
	    }
#if 0
	    if (timeout.tv_sec > now.tv_sec)
		debug(DBG_DBG, "clientwr: waiting up to %ld secs for new request", timeout.tv_sec - now.tv_sec);
#endif
	    pthread_cond_timedwait(&server->newrq_cond, &server->newrq_mutex, &timeout);
	    timeout.tv_sec = 0;
	}
	if (server->newrq) {
	    debug(DBG_DBG, "clientwr: got new request");
	    server->newrq = 0;
	}
    if (server->conreset) {
        debug(DBG_DBG, "clientwr: connection reset; resending all aoutstanding requests");
        do_resend = 1;
        server->conreset = 0;
    }
#if 0
	else
	    debug(DBG_DBG, "clientwr: request timer expired, processing request queue");
#endif
	pthread_mutex_unlock(&server->newrq_mutex);

    if (do_resend || server->lastrcv.tv_sec > laststatsrv.tv_sec)
        statusserver_requested = 0;

    for (i = 0; i < MAX_REQUESTS; i++) {
        if (server->clientrdgone) {
		server->state = RSP_SERVER_STATE_FAILING;
                if (conf->pdef->connecter)
                    pthread_join(clientrdth, NULL);
		goto errexit;
	    }

	    for (; i < MAX_REQUESTS; i++) {
		rqout = server->requests + i;
		if (rqout->rq) {
		    pthread_mutex_lock(rqout->lock);
		    if (rqout->rq)
			break;
		    pthread_mutex_unlock(rqout->lock);
		}
	    }

	    if (i == MAX_REQUESTS)
		break;

        gettimeofday(&now, NULL);
        if (do_resend) {
            if (rqout->tries > 0)
                rqout->tries--;
        } else if (now.tv_sec < rqout->expiry.tv_sec) {
            if (!timeout.tv_sec || rqout->expiry.tv_sec < timeout.tv_sec)
                timeout.tv_sec = rqout->expiry.tv_sec;
            pthread_mutex_unlock(rqout->lock);
            continue;
        }

        if (rqout->tries > 0 && now.tv_sec - server->lastrcv.tv_sec > conf->retryinterval && !do_resend)
            statusserver_requested = 1;
        if (rqout->tries == (*rqout->rq->buf == RAD_Status_Server ? 1 : conf->retrycount + 1)) {
            debug(DBG_DBG, "clientwr: removing expired packet from queue");
            replylog(rqout->rq->msg, server, rqout->rq);
            if (conf->statusserver == RSP_STATSRV_ON || conf->statusserver == RSP_STATSRV_MINIMAL) {
                if (*rqout->rq->buf == RAD_Status_Server) {
                    debug(DBG_WARN, "clientwr: no status server response, %s dead?", conf->name);
                    if (server->lostrqs < MAX_LOSTRQS)
                        server->lostrqs++;
                }
            } else {
                if (conf->statusserver == RSP_STATSRV_AUTO && *rqout->rq->buf == RAD_Status_Server) {
                    if (server->lastreply.tv_sec >= laststatsrv.tv_sec) {
                        debug(DBG_DBG, "clientwr: status server autodetect failed, disabling status server for %s", conf->name);
                        conf->statusserver = RSP_STATSRV_OFF;
                    }
                } else {
                    debug(DBG_WARN, "clientwr: no server response, %s dead?", conf->name);
                    if (server->lostrqs < MAX_LOSTRQS)
                        server->lostrqs++;
                }
            }
            freerqoutdata(rqout);
            pthread_mutex_unlock(rqout->lock);
            continue;
        }

	    rqout->expiry.tv_sec = now.tv_sec + conf->retryinterval;
	    if (!timeout.tv_sec || rqout->expiry.tv_sec < timeout.tv_sec)
		timeout.tv_sec = rqout->expiry.tv_sec;
	    rqout->tries++;
	    if (!conf->pdef->clientradput(server, rqout->rq->buf)) {
            debug(DBG_WARN, "clientwr: could not send request to server %s", conf->name);
            if (server->lostrqs < MAX_LOSTRQS)
                server->lostrqs++;
        }
	    pthread_mutex_unlock(rqout->lock);
	}
    do_resend = 0;
    if (server->state == RSP_SERVER_STATE_CONNECTED && !(conf->statusserver == RSP_STATSRV_OFF)) {
        gettimeofday(&now, NULL);
        if ((conf->statusserver == RSP_STATSRV_ON && now.tv_sec - (server->lastrcv.tv_sec > laststatsrv.tv_sec ? server->lastrcv.tv_sec : laststatsrv.tv_sec) > STATUS_SERVER_PERIOD) ||
            (conf->statusserver == RSP_STATSRV_MINIMAL && statusserver_requested && now.tv_sec - laststatsrv.tv_sec > STATUS_SERVER_PERIOD) ||
            (conf->statusserver == RSP_STATSRV_AUTO && server->lastreply.tv_sec >= laststatsrv.tv_sec)) {

            laststatsrv = now;
            statsrvrq = createstatsrvrq();
            if (statsrvrq) {
                statsrvrq->to = server;
                debug(DBG_DBG, "clientwr: sending %s to %s", radmsgtype2string(RAD_Status_Server), conf->name);
                sendrq(statsrvrq);
            }
            statusserver_requested = 0;
        }
    }
    }
errexit:
    if (server->dynamiclookuparg) {
	removeserversubrealms(realms, conf);
	if (dynconffail)
	    free(conf);
	else
	    freeclsrvconf(conf);
    }
    freeserver(server, 1);
    return NULL;
}

void createlistener(uint8_t type, char *arg) {
    pthread_t th;
    struct addrinfo *res;
    int s = -1, on = 1, *sp = NULL;
    struct hostportres *hp = newhostport(arg, protodefs[type]->portdefault, 0);

    if (!hp || !resolvehostport(hp, AF_UNSPEC, protodefs[type]->socktype, 1))
	debugx(1, DBG_ERR, "createlistener: failed to resolve %s", arg);

    for (res = hp->addrinfo; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            debugerrno(errno, DBG_WARN, "createlistener: socket failed");
            continue;
        }
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
            debugerrno(errno, DBG_WARN, "createlistener: SO_REUSEADDR");

	disable_DF_bit(s, res);

#ifdef IPV6_V6ONLY
	if (res->ai_family == AF_INET6)
	    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1)
                debugerrno(errno, DBG_WARN, "createlistener: IPV6_V6ONLY");
#endif
    if (res->ai_socktype == SOCK_DGRAM) {
        if (res->ai_family == AF_INET6) {
            if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == -1)
                debugerrno(errno, DBG_WARN, "craetelistener: IPV6_RECVPKTINFO");
        } else if (res->ai_family == AF_INET) {
#if defined(IP_PKTINFO)
            if (setsockopt(s, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == -1)
                debugerrno(errno, DBG_WARN, "createlistener: IP_PKTINFO");
#elif defined(IP_RECVDSTADDR)
            if (setsockopt(s, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on)) == -1)
                debugerrno(errno, DBG_WARN, "createlistener: IP_RECVDSTADDR");
#endif
        }
    }
	if (bind(s, res->ai_addr, res->ai_addrlen)) {
	    debugerrno(errno, DBG_WARN, "createlistener: bind failed");
	    close(s);
	    continue;
	}

	sp = malloc(sizeof(int));
        if (!sp)
            debugx(1, DBG_ERR, "malloc failed");
	*sp = s;
	if (pthread_create(&th, &pthread_attr, protodefs[type]->listener, (void *)sp))
            debugerrnox(errno, DBG_ERR, "pthread_create failed");
	pthread_detach(th);
    }
    if (!sp)
	debugx(1, DBG_ERR, "createlistener: socket/bind failed");

    debug(DBG_WARN, "createlistener: listening for %s on %s:%s", protodefs[type]->name, hp->host ? hp->host : "*", hp->port);
    freehostport(hp);
}

void createlisteners(uint8_t type) {
    int i;
    char **args;

    args = protodefs[type]->getlistenerargs();
    if (args)
	for (i = 0; args[i]; i++)
	    createlistener(type, args[i]);
    else
	createlistener(type, NULL);
}

void randinit() {
    time_t t;
    pid_t pid;

    while (!RAND_status()) {
	t = time(NULL);
	pid = getpid();
	RAND_seed((unsigned char *)&t, sizeof(time_t));
	RAND_seed((unsigned char *)&pid, sizeof(pid));
    }
}

struct list *addsrvconfs(char *value, char **names) {
    struct list *conflist;
    int n;
    struct list_node *entry;
    struct clsrvconf *conf = NULL;

    if (!names || !*names)
	return NULL;

    conflist = list_create();
    if (!conflist) {
	debug(DBG_ERR, "malloc failed");
	return NULL;
    }

    for (n = 0; names[n]; n++) {
	for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	    conf = (struct clsrvconf *)entry->data;
	    if (!strcasecmp(names[n], conf->name))
		break;
	}
	if (!entry) {
	    debug(DBG_ERR, "addsrvconfs failed for realm %s, no server named %s", value, names[n]);
	    list_free(conflist);
	    return NULL;
	}
	if (!list_push(conflist, conf)) {
	    debug(DBG_ERR, "malloc failed");
	    list_free(conflist);
	    return NULL;
	}
	debug(DBG_DBG, "addsrvconfs: added server %s for realm %s", conf->name, value);
    }
    return conflist;
}

void freerealm(struct realm *realm) {
    if (!realm)
	return;
    debug(DBG_DBG, "freerealm: called with refcount %d", realm->refcount);
    pthread_mutex_lock(&realm->refmutex);
    if (--realm->refcount) {
        pthread_mutex_unlock(&realm->refmutex);
        return;
    }
    pthread_mutex_unlock(&realm->refmutex);

    free(realm->name);
    free(realm->message);
    regfree(&realm->regex);
    pthread_mutex_destroy(&realm->refmutex);
    pthread_mutex_destroy(&realm->mutex);
    /* if refcount == 0, all subrealms gone */
    list_destroy(realm->subrealms);
    /* if refcount == 0, all srvconfs gone */
    list_destroy(realm->srvconfs);
    /* if refcount == 0, all accsrvconfs gone */
    list_destroy(realm->accsrvconfs);
    freerealm(realm->parent);
    free(realm);
}

struct realm *addrealm(struct list *realmlist, char *value, char **servers,
                       char **accservers, char **dynauthservers, char *message,
                       uint8_t accresp) {
    int n;
    struct realm *realm;
    char *s, *regex = NULL;

    if (*value == '/') {
	/* regexp, remove optional trailing / if present */
	if (value[strlen(value) - 1] == '/')
	    value[strlen(value) - 1] = '\0';
    } else {
	/* not a regexp, let us make it one */
	if (*value == '*' && !value[1])
	    regex = stringcopy(".*", 0);
	else {
	    for (n = 0, s = value; *s;)
		if (*s++ == '.')
		    n++;
	    regex = malloc(strlen(value) + n + 3);
	    if (regex) {
		regex[0] = '@';
		for (n = 1, s = value; *s; s++) {
		    if (*s == '.')
			regex[n++] = '\\';
		    regex[n++] = *s;
		}
		regex[n++] = '$';
		regex[n] = '\0';
	    }
	}
	if (!regex) {
	    debug(DBG_ERR, "malloc failed");
	    realm = NULL;
	    goto exit;
	}
	debug(DBG_DBG, "addrealm: constructed regexp %s from %s", regex, value);
    }

    realm = malloc(sizeof(struct realm));
    if (!realm) {
	debug(DBG_ERR, "malloc failed");
	goto exit;
    }
    memset(realm, 0, sizeof(struct realm));

    if (pthread_mutex_init(&realm->mutex, NULL) ||
        pthread_mutex_init(&realm->refmutex, NULL)) {
	debugerrno(errno, DBG_ERR, "mutex init failed");
	free(realm);
	realm = NULL;
	goto exit;
    }
	newrealmref(realm);

    realm->name = stringcopy(value, 0);
    if (!realm->name) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    if (message && strlen(message) > 253) {
	debug(DBG_ERR, "ReplyMessage can be at most 253 bytes");
	goto errexit;
    }
    realm->message = message;
    realm->accresp = accresp;

    if (regcomp(&realm->regex, regex ? regex : value + 1, REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
	debug(DBG_ERR, "addrealm: failed to compile regular expression %s", regex ? regex : value + 1);
	goto errexit;
    }

    if (servers && *servers) {
	realm->srvconfs = addsrvconfs(value, servers);
	if (!realm->srvconfs)
	    goto errexit;
    }

    if (accservers && *accservers) {
	realm->accsrvconfs = addsrvconfs(value, accservers);
	if (!realm->accsrvconfs)
	    goto errexit;
    }

    if (dynauthservers && *dynauthservers) {
        realm->dynauthsrvconfs = addsrvconfs(value, dynauthservers);
        if (!realm->dynauthsrvconfs) {
            goto errexit;
        }
    }

    if (!list_push(realmlist, realm)) {
	debug(DBG_ERR, "malloc failed");
	pthread_mutex_destroy(&realm->mutex);
	goto errexit;
    }

    debug(DBG_DBG, "addrealm: added realm %s", value);
    goto exit;

errexit:
    while (list_shift(realm->srvconfs));
    while (list_shift(realm->accsrvconfs));
    freerealm(realm);
    realm = NULL;
exit:
    free(regex);
    if (servers) {
	if (realm)
	    for (n = 0; servers[n]; n++)
		newrealmref(realm);
	freegconfmstr(servers);
    }
    if (accservers) {
	if (realm)
	    for (n = 0; accservers[n]; n++)
		newrealmref(realm);
	freegconfmstr(accservers);
    }
    return realm;
}

struct list *createsubrealmservers(struct realm *realm, struct list *srvconfs) {
    struct list_node *entry;
    struct clsrvconf *conf, *srvconf;
    struct list *subrealmservers = NULL;
    pthread_t clientth;

    if (list_first(srvconfs)) {
	subrealmservers = list_create();
	if (!subrealmservers)
	    return NULL;
    }

    for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	conf = (struct clsrvconf *)entry->data;
	if (!conf->servers && conf->dynamiclookupcommand) {
	    srvconf = malloc(sizeof(struct clsrvconf));
	    if (!srvconf) {
		debug(DBG_ERR, "malloc failed");
		continue;
	    }
            debug(DBG_DBG, "%s: copying config %s", __func__, conf->name);
	    *srvconf = *conf;
            /* Shallow copy -- sharing all the pointers.  addserver()
             * will take care of servers (which btw has to be NUL) but
             * the rest of them are shared with the config found in
             * the srvconfs list.  */
	    if (addserver(srvconf)) {
		srvconf->servers->dynamiclookuparg = stringcopy(realm->name, 0);
		srvconf->servers->state = RSP_SERVER_STATE_STARTUP;
                debug(DBG_DBG, "%s: new client writer for %s",
                      __func__, srvconf->servers->conf->name);
		if (pthread_create(&clientth, &pthread_attr, clientwr, (void *)(srvconf->servers))) {
		    debugerrno(errno, DBG_ERR, "pthread_create failed");
		    freeserver(srvconf->servers, 1);
		    srvconf->servers = NULL;
		} else
		    pthread_detach(clientth);

	    }
	    conf = srvconf;
	}
	if (conf->servers) {
	    if (list_push(subrealmservers, conf))
		newrealmref(realm);
	    else
		debug(DBG_ERR, "malloc failed");
	}
    }
    return subrealmservers;
}

struct realm *adddynamicrealmserver(struct realm *realm, char *id) {
    struct realm *newrealm = NULL;
    char *realmname, *s;

    /* create dynamic for the realm (string after last @, exit if nothing after @ */
    realmname = strrchr(id, '@');
    if (!realmname)
	return NULL;
    realmname++;
    if (!*realmname)
	return NULL;
    for (s = realmname; *s; s++)
	if (*s != '.' && *s != '-' && !isalnum((int)*s))
	    return NULL;

    if (!realm->subrealms)
	realm->subrealms = list_create();
    if (!realm->subrealms)
	return NULL;

    newrealm = addrealm(realm->subrealms, realmname, NULL, NULL, NULL,
                        stringcopy(realm->message, 0), realm->accresp);
    if (!newrealm) {
	list_destroy(realm->subrealms);
	realm->subrealms = NULL;
	return NULL;
    }

    newrealm->parent = newrealmref(realm);
    /* add server and accserver to newrealm */
    newrealm->srvconfs = createsubrealmservers(newrealm, realm->srvconfs);
    newrealm->accsrvconfs = createsubrealmservers(newrealm, realm->accsrvconfs);
    newrealm->dynauthsrvconfs = createsubrealmservers(newrealm, realm->dynauthsrvconfs);
    return newrealm;
}

int dynamicconfig(struct server *server) {
    int ok, fd[2], status;
    pid_t pid;
    struct clsrvconf *conf = server->conf;
    struct gconffile *cf = NULL;

    /* for now we only learn hostname/address */
    debug(DBG_DBG, "dynamicconfig: need dynamic server config for %s", server->dynamiclookuparg);

    if (pipe(fd) > 0) {
	debugerrno(errno, DBG_ERR, "dynamicconfig: pipe error");
	goto errexit;
    }
    pid = fork();
    if (pid < 0) {
	debugerrno(errno, DBG_ERR, "dynamicconfig: fork error");
	close(fd[0]);
	close(fd[1]);
	goto errexit;
    } else if (pid == 0) {
	/* child */
	close(fd[0]);
	if (fd[1] != STDOUT_FILENO) {
	    if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO)
		debugx(1, DBG_ERR, "dynamicconfig: dup2 error for command %s", conf->dynamiclookupcommand);
	    close(fd[1]);
	}
	if (execlp(conf->dynamiclookupcommand, conf->dynamiclookupcommand, server->dynamiclookuparg, NULL) < 0)
	    debugx(1, DBG_ERR, "dynamicconfig: exec error for command %s", conf->dynamiclookupcommand);
    }

    close(fd[1]);
    pushgconffile(&cf, fdopen(fd[0], "r"), conf->dynamiclookupcommand);
    ok = getgenericconfig(&cf, NULL, "Server", CONF_CBK, confserver_cb,
			  (void *) conf, NULL);
    freegconf(&cf);

    if (waitpid(pid, &status, 0) < 0) {
	debugerrno(errno, DBG_ERR, "dynamicconfig: wait error");
	goto errexit;
    }

    if (status) {
        debug(DBG_INFO, "dynamicconfig: command exited with status %d",
              WEXITSTATUS(status));
        goto errexit;
    }

    if (ok)
	return 1;

errexit:
    debug(DBG_WARN, "dynamicconfig: failed to obtain dynamic server config");
    return 0;
}

int setttlattr(struct options *opts, char *defaultattr) {
    char *ttlattr = opts->ttlattr ? opts->ttlattr : defaultattr;

    if (vattrname2val(ttlattr, opts->ttlattrtype, opts->ttlattrtype + 1) &&
	(opts->ttlattrtype[1] != 256 || opts->ttlattrtype[0] < 256))
	return 1;
    debug(DBG_ERR, "setttlattr: invalid TTLAttribute value %s", ttlattr);
    return 0;
}

void freeclsrvconf(struct clsrvconf *conf) {
    assert(conf);
    debug(DBG_DBG, "%s: freeing %p (%s)", __func__, conf, conf->name ? conf->name : "incomplete");
    free(conf->name);
    if (conf->hostsrc)
	freegconfmstr(conf->hostsrc);
    free(conf->portsrc);
    freegconfmstr(conf->source);
    free(conf->confsecret);
    free(conf->secret);
    free(conf->tls);
    freegconfmstr(conf->confmatchcertattrs);
    freematchcertattr(conf);
    free(conf->confrewritein);
    free(conf->confrewriteout);
    if (conf->rewriteusername) {
	if (conf->rewriteusername->regex)
	    regfree(conf->rewriteusername->regex);
	free(conf->rewriteusername->replacement);
	free(conf->rewriteusername);
    }
    free(conf->dynamiclookupcommand);
    conf->rewritein=NULL;
    conf->rewriteout=NULL;
    if (conf->hostports)
	freehostports(conf->hostports);
    if (conf->lock) {
	pthread_mutex_destroy(conf->lock);
	free(conf->lock);
    }
    /* not touching ssl_ctx, clients and servers */
    free(conf);
}

int mergeconfstring(char **dst, char **src) {
    char *t;

    if (*src) {
	*dst = *src;
	*src = NULL;
	return 1;
    }
    if (*dst) {
	t = stringcopy(*dst, 0);
	if (!t) {
	    debug(DBG_ERR, "malloc failed");
	    return 0;
	}
	*dst = t;
    }
    return 1;
}

char **mstringcopy(char **in) {
    char **out;
    int n;

    if (!in)
	return NULL;

    for (n = 0; in[n]; n++);
    out = malloc((n + 1) * sizeof(char *));
    if (!out)
	return NULL;
    for (n = 0; in[n]; n++) {
	out[n] = stringcopy(in[n], 0);
	if (!out[n]) {
	    freegconfmstr(out);
	    return NULL;
	}
    }
    out[n] = NULL;
    return out;
}

int mergeconfmstring(char ***dst, char ***src) {
    char **t;

    if (*src) {
	*dst = *src;
	*src = NULL;
	return 1;
    }
    if (*dst) {
	t = mstringcopy(*dst);
	if (!t) {
	    debug(DBG_ERR, "malloc failed");
	    return 0;
	}
	*dst = t;
    }
    return 1;
}

/* assumes dst is a shallow copy */
int mergesrvconf(struct clsrvconf *dst, struct clsrvconf *src) {
    if (!mergeconfstring(&dst->name, &src->name) ||
	!mergeconfmstring(&dst->hostsrc, &src->hostsrc) ||
	!mergeconfstring(&dst->portsrc, &src->portsrc) ||
    !mergeconfmstring(&dst->source, &src->source) ||
	!mergeconfstring(&dst->confsecret, &src->confsecret) ||
	!mergeconfstring(&dst->tls, &src->tls) ||
	!mergeconfmstring(&dst->confmatchcertattrs, &src->confmatchcertattrs) ||
	!mergeconfstring(&dst->confrewritein, &src->confrewritein) ||
	!mergeconfstring(&dst->confrewriteout, &src->confrewriteout) ||
	!mergeconfstring(&dst->confrewriteusername, &src->confrewriteusername) ||
	!mergeconfstring(&dst->dynamiclookupcommand, &src->dynamiclookupcommand) ||
	!mergeconfstring(&dst->fticks_viscountry, &src->fticks_viscountry) ||
	!mergeconfstring(&dst->fticks_visinst, &src->fticks_visinst))
	return 0;
    if (src->pdef)
	dst->pdef = src->pdef;
    dst->statusserver = src->statusserver;
    dst->certnamecheck = src->certnamecheck;
    if (src->retryinterval != 255)
	dst->retryinterval = src->retryinterval;
    if (src->retrycount != 255)
	dst->retrycount = src->retrycount;
    return 1;
}

/** Set *AF according to IPV4ONLY and IPV6ONLY:
    - If both are set, the function fails.
    - If exactly one is set, *AF is set accordingly.
    - If none is set, *AF is not affected.
    Return 0 on success and !0 on failure.
    In the case of an error, *AF is not affected.  */
int config_hostaf(const char *desc, int ipv4only, int ipv6only, int *af) {
    assert(af != NULL);
    if (ipv4only && ipv6only) {
	debug(DBG_ERR, "error in block %s, at most one of IPv4Only and "
              "IPv6Only can be enabled", desc);
        return -1;
    }
    if (ipv4only)
        *af = AF_INET;
    if (ipv6only)
        *af = AF_INET6;
    return 0;
}

int confclient_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    struct clsrvconf *conf, *existing;
    char *conftype = NULL, *rewriteinalias = NULL, **matchcertattrs = NULL;
    long int dupinterval = LONG_MIN, addttl = LONG_MIN;
    uint8_t ipv4only = 0, ipv6only = 0;
    struct list_node *entry;
    int i;

    debug(DBG_DBG, "confclient_cb called for %s", block);

    conf = malloc(sizeof(struct clsrvconf));
    if (!conf)
	debugx(1, DBG_ERR, "malloc failed");
    memset(conf, 0, sizeof(struct clsrvconf));
    conf->certnamecheck = 1;

    if (!getgenericconfig(
	    cf, block,
	    "type", CONF_STR, &conftype,
	    "host", CONF_MSTR, &conf->hostsrc,
            "IPv4Only", CONF_BLN, &ipv4only,
            "IPv6Only", CONF_BLN, &ipv6only,
	    "secret", CONF_STR_NOESC, &conf->confsecret,
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
	    "tls", CONF_STR, &conf->tls,
	    "matchcertificateattribute", CONF_MSTR, &matchcertattrs,
	    "CertificateNameCheck", CONF_BLN, &conf->certnamecheck,
#endif
	    "DuplicateInterval", CONF_LINT, &dupinterval,
	    "addTTL", CONF_LINT, &addttl,
        "tcpKeepalive", CONF_BLN, &conf->keepalive,
	    "rewrite", CONF_STR, &rewriteinalias,
	    "rewriteIn", CONF_STR, &conf->confrewritein,
	    "rewriteOut", CONF_STR, &conf->confrewriteout,
	    "rewriteattribute", CONF_STR, &conf->confrewriteusername,
	    "fticksVISCOUNTRY", CONF_STR, &conf->fticks_viscountry,
	    "fticksVISINST", CONF_STR, &conf->fticks_visinst,
	    NULL
	    ))
	debugx(1, DBG_ERR, "configuration error");

    conf->name = stringcopy(val, 0);
    if (conf->name && !conf->hostsrc) {
	conf->hostsrc = malloc(2 * sizeof(char *));
	if (conf->hostsrc) {
	    conf->hostsrc[0] = stringcopy(val, 0);
	    conf->hostsrc[1] = NULL;
	}
    }
    if (!conf->name || !conf->hostsrc || !conf->hostsrc[0])
	debugx(1, DBG_ERR, "malloc failed");

    if (!conftype)
	debugx(1, DBG_ERR, "error in block %s, option type missing", block);
    conf->type = protoname2int(conftype);
    if (conf->type == 255)
	debugx(1, DBG_ERR, "error in block %s, unknown transport %s", block, conftype);
    free(conftype);
    conf->pdef = protodefs[conf->type];

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
    if (conf->type == RAD_TLS || conf->type == RAD_DTLS) {
        conf->tlsconf = conf->tls
                ? tlsgettls(conf->tls, NULL)
                : tlsgettls("defaultClient", "default");
        if (!conf->tlsconf)
            debugx(1, DBG_ERR, "error in block %s, no tls context defined", block);
        if (matchcertattrs) {
            for (i=0; matchcertattrs[i]; i++){
                if (!addmatchcertattr(conf, matchcertattrs[i])) {
                    debugx(1, DBG_ERR, "error in block %s, invalid MatchCertificateAttributeValue", block);
                }
            }
            freegconfmstr(matchcertattrs);
        }
    }
#endif

    conf->hostaf = AF_UNSPEC;
    if (config_hostaf("top level", options.ipv4only, options.ipv6only, &conf->hostaf))
        debugx(1, DBG_ERR, "config error: ^");
    if (config_hostaf(block, ipv4only, ipv6only, &conf->hostaf))
        debugx(1, DBG_ERR, "error in block %s: ^", block);

    if (dupinterval != LONG_MIN) {
	if (dupinterval < 0 || dupinterval > 255)
	    debugx(1, DBG_ERR, "error in block %s, value of option DuplicateInterval is %d, must be 0-255", block, dupinterval);
	conf->dupinterval = (uint8_t)dupinterval;
    } else
	conf->dupinterval = conf->pdef->duplicateintervaldefault;

    if (addttl != LONG_MIN) {
	if (addttl < 1 || addttl > 255)
	    debugx(1, DBG_ERR, "error in block %s, value of option addTTL is %d, must be 1-255", block, addttl);
	conf->addttl = (uint8_t)addttl;
    }

    if (!conf->confrewritein)
	conf->confrewritein = rewriteinalias;
    else
	free(rewriteinalias);
    conf->rewritein = conf->confrewritein
        ? getrewrite(conf->confrewritein, NULL)
        : getrewrite("defaultClient", "default");
    if (conf->confrewriteout)
	conf->rewriteout = getrewrite(conf->confrewriteout, NULL);

    if (conf->confrewriteusername) {
	conf->rewriteusername = extractmodattr(conf->confrewriteusername);
	if (!conf->rewriteusername)
	    debugx(1, DBG_ERR, "error in block %s, invalid RewriteAttributeValue", block);
    }

    if (!addhostport(&conf->hostports, conf->hostsrc, conf->pdef->portdefault, 1) ||
	!resolvehostports(conf->hostports, conf->hostaf, conf->pdef->socktype))
	debugx(1, DBG_ERR, "%s: resolve failed, exiting", __func__);

    if (!conf->confsecret) {
	if (!conf->pdef->secretdefault)
	    debugx(1, DBG_ERR, "error in block %s, secret must be specified for transport type %s", block, conf->pdef->name);
	conf->confsecret = stringcopy(conf->pdef->secretdefault, 0);
	if (!conf->confsecret)
	    debugx(1, DBG_ERR, "malloc failed");
    }
    conf->secret = (unsigned char *)stringcopy(conf->confsecret, 0);
    conf->secret_len = unhex((char *)conf->secret, 1);

    if (conf->tlsconf) {
        for (entry = list_first(clconfs); entry; entry = list_next(entry)) {
            existing = (struct clsrvconf *)entry->data;

            if (existing->type == conf->type &&
                existing->tlsconf != conf->tlsconf &&
                hostportmatches(existing->hostports, conf->hostports, 0)) {

                debugx(1, DBG_ERR, "error in block %s, overlapping clients must reference the same tls block", block);
            }
        }
    }

    conf->lock = malloc(sizeof(pthread_mutex_t));
    if (!conf->lock)
	debugx(1, DBG_ERR, "malloc failed");

    pthread_mutex_init(conf->lock, NULL);
    if (!list_push(clconfs, conf))
	debugx(1, DBG_ERR, "malloc failed");
    return 1;
}

int compileserverconfig(struct clsrvconf *conf, const char *block) {
    int i;
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
    if (conf->type == RAD_TLS || conf->type == RAD_DTLS) {
    	conf->tlsconf = conf->tls
            ? tlsgettls(conf->tls, NULL)
            : tlsgettls("defaultServer", "default");
        if (!conf->tlsconf) {
            debug(DBG_ERR, "error in block %s, no tls context defined", block);
            return 0;
        }
        if (conf->confmatchcertattrs) {
            for (i=0; conf->confmatchcertattrs[i]; i++){
                if (!addmatchcertattr(conf, conf->confmatchcertattrs[i])) {
                    debugx(1, DBG_ERR, "error in block %s, invalid MatchCertificateAttributeValue", block);
                }
            }
        }
    }
#endif

    if (!conf->portsrc) {
        conf->portsrc = stringcopy(conf->pdef->portdefault, 0);
	if (!conf->portsrc) {
	    debug(DBG_ERR, "malloc failed");
	    return 0;
	}
    }

    if (conf->retryinterval == 255)
	conf->retryinterval = conf->pdef->retryintervaldefault;
    if (conf->retrycount == 255)
	conf->retrycount = conf->pdef->retrycountdefault;

    conf->rewritein = conf->confrewritein
        ? getrewrite(conf->confrewritein, NULL)
        : getrewrite("defaultServer", "default");
    if (conf->confrewriteout)
	conf->rewriteout = getrewrite(conf->confrewriteout, NULL);

    if (!addhostport(&conf->hostports, conf->hostsrc, conf->portsrc, 0)) {
	debug(DBG_ERR, "error in block %s, failed to parse %s", block, *conf->hostsrc);
	return 0;
    }

    if (!conf->dynamiclookupcommand &&
        !resolvehostports(conf->hostports, conf->hostaf,
                          conf->pdef->socktype)) {
	debug(DBG_ERR, "%s: resolve failed", __func__);
	return 0;
    }
    return 1;
}

int confserver_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    struct clsrvconf *conf, *resconf;
    char *conftype = NULL, *rewriteinalias = NULL, *statusserver = NULL;
    long int retryinterval = LONG_MIN, retrycount = LONG_MIN, addttl = LONG_MIN;
    uint8_t ipv4only = 0, ipv6only = 0, confmerged = 0;

    debug(DBG_DBG, "confserver_cb called for %s", block);

    conf = malloc(sizeof(struct clsrvconf));
    if (!conf) {
	debug(DBG_ERR, "malloc failed");
	return 0;
    }
    memset(conf, 0, sizeof(struct clsrvconf));
    conf->loopprevention = UCHAR_MAX; /* Uninitialized.  */
    resconf = (struct clsrvconf *)arg;
    if (resconf) {
        conf->statusserver = resconf->statusserver;
        conf->certnamecheck = resconf->certnamecheck;
    } else {
        conf->certnamecheck = 1;
    }

    if (!getgenericconfig(cf, block,
            "type", CONF_STR, &conftype,
            "host", CONF_MSTR, &conf->hostsrc,
                          "IPv4Only", CONF_BLN, &ipv4only,
                          "IPv6Only", CONF_BLN, &ipv6only,
            "port", CONF_STR, &conf->portsrc,
            "source", CONF_MSTR, &conf->source,
            "secret", CONF_STR_NOESC, &conf->confsecret,
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
            "tls", CONF_STR, &conf->tls,
            "MatchCertificateAttribute", CONF_STR, &conf->confmatchcertattrs,
            "CertificateNameCheck", CONF_BLN, &conf->certnamecheck,
#endif
            "addTTL", CONF_LINT, &addttl,
            "tcpKeepalive", CONF_BLN, &conf->keepalive,
            "rewrite", CONF_STR, &rewriteinalias,
            "rewriteIn", CONF_STR, &conf->confrewritein,
            "rewriteOut", CONF_STR, &conf->confrewriteout,
            "StatusServer", CONF_STR, &statusserver,
            "RetryInterval", CONF_LINT, &retryinterval,
            "RetryCount", CONF_LINT, &retrycount,
            "DynamicLookupCommand", CONF_STR, &conf->dynamiclookupcommand,
            "LoopPrevention", CONF_BLN, &conf->loopprevention,
            NULL
	    )) {
	debug(DBG_ERR, "configuration error");
	goto errexit;
    }

    conf->name = stringcopy(val, 0);
    if (conf->name && !conf->hostsrc) {
	conf->hostsrc = malloc(2 * sizeof(char *));
	if (conf->hostsrc) {
	    conf->hostsrc[0] = stringcopy(val, 0);
	    conf->hostsrc[1] = NULL;
	}
    }
    if (!conf->name || !conf->hostsrc || !conf->hostsrc[0]) {
        debug(DBG_ERR, "malloc failed");
	goto errexit;
    }

    if (!conftype) {
	debug(DBG_ERR, "error in block %s, option type missing", block);
	goto errexit;
    }
    conf->type = protoname2int(conftype);
    if (conf->type == 255) {
	debug(DBG_ERR, "error in block %s, unknown transport %s", block, conftype);
	goto errexit;
    }
    free(conftype);
    conftype = NULL;

    conf->hostaf = AF_UNSPEC;
    if (config_hostaf("top level", options.ipv4only, options.ipv6only, &conf->hostaf))
        debugx(1, DBG_ERR, "config error: ^");
    if (config_hostaf(block, ipv4only, ipv6only, &conf->hostaf))
        goto errexit;

    conf->pdef = protodefs[conf->type];

    if (!conf->confrewritein)
	conf->confrewritein = rewriteinalias;
    else
	free(rewriteinalias);
    rewriteinalias = NULL;

    if (retryinterval != LONG_MIN) {
	if (retryinterval < 1 || retryinterval > conf->pdef->retryintervalmax) {
	    debug(DBG_ERR, "error in block %s, value of option RetryInterval is %d, must be 1-%d", block, retryinterval, conf->pdef->retryintervalmax);
	    goto errexit;
	}
	conf->retryinterval = (uint8_t)retryinterval;
    } else
	conf->retryinterval = 255;

    if (retrycount != LONG_MIN) {
	if (retrycount < 0 || retrycount > conf->pdef->retrycountmax) {
	    debug(DBG_ERR, "error in block %s, value of option RetryCount is %d, must be 0-%d", block, retrycount, conf->pdef->retrycountmax);
	    goto errexit;
	}
	conf->retrycount = (uint8_t)retrycount;
    } else
	conf->retrycount = 255;

    if (addttl != LONG_MIN) {
	if (addttl < 1 || addttl > 255) {
	    debug(DBG_ERR, "error in block %s, value of option addTTL is %d, must be 1-255", block, addttl);
	    goto errexit;
	}
	conf->addttl = (uint8_t)addttl;
    }

    if (statusserver) {
        if (strcasecmp(statusserver, "Off") == 0)
            conf->statusserver = RSP_STATSRV_OFF;
        else if (strcasecmp(statusserver, "On") == 0)
            conf->statusserver = RSP_STATSRV_ON;
        else if (strcasecmp(statusserver, "Minimal") == 0)
            conf->statusserver = RSP_STATSRV_MINIMAL;
        else if (strcasecmp(statusserver, "Auto") == 0)
            conf->statusserver = RSP_STATSRV_AUTO;
        else
            debugx(1, DBG_ERR, "config error in blocck %s: invalid StatusServer value: %s", block, statusserver);
    }

    if (resconf) {
        if (!mergesrvconf(resconf, conf))
            goto errexit;
        free(conf);
        conf = resconf;
        confmerged = 1;
        if (conf->dynamiclookupcommand) {
            free(conf->dynamiclookupcommand);
            conf->dynamiclookupcommand = NULL;
        }
    }

    if (resconf || !conf->dynamiclookupcommand) {
	if (!compileserverconfig(conf, block))
            goto errexit;
    }

    if (!conf->confsecret) {
	if (!conf->pdef->secretdefault) {
	    debug(DBG_ERR, "error in block %s, secret must be specified for transport type %s", block, conf->pdef->name);
	    goto errexit;
	}
	conf->confsecret = stringcopy(conf->pdef->secretdefault, 0);
	if (!conf->confsecret) {
	    debug(DBG_ERR, "malloc failed");
	    goto errexit;
	}
    }
    conf->secret = (unsigned char *)stringcopy(conf->confsecret,0);
    conf->secret_len = unhex((char *)conf->secret,1);

    if (resconf)
	return 1;

    if (!list_push(srvconfs, conf)) {
	debug(DBG_ERR, "malloc failed");
	goto errexit;
    }
    return 1;

errexit:
    free(conftype);
    free(rewriteinalias);
    /* if conf was merged into resconf, don't free it */
    if (!confmerged)
        freeclsrvconf(conf);
    return 0;
}

int confrewrite_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    uint8_t whitelist_mode = 0;
    char **rmattrs = NULL, **rmvattrs = NULL;
    char **wlattrs = NULL, **wlvattrs = NULL;
    char **addattrs = NULL, **addvattrs = NULL;
    char **modattrs = NULL, **modvattrs = NULL;
    char **supattrs = NULL, **supvattrs = NULL;

    debug(DBG_DBG, "confrewrite_cb called for %s", block);

    if (!getgenericconfig(cf, block,
        "whitelistMode", CONF_BLN, &whitelist_mode,
        "removeAttribute", CONF_MSTR, &rmattrs,
        "removeVendorAttribute", CONF_MSTR, &rmvattrs,
        "whitelistAttribute", CONF_MSTR, &wlattrs,
        "whitelistVendorAttribute", CONF_MSTR, &wlvattrs,
        "addAttribute", CONF_MSTR_NOESC, &addattrs,
        "addVendorAttribute", CONF_MSTR_NOESC, &addvattrs,
        "modifyAttribute", CONF_MSTR, &modattrs,
        "modifyVendorAttribute", CONF_MSTR, &modvattrs,
        "supplementAttribute", CONF_MSTR_NOESC, &supattrs,
        "supplementVendorAttribute", CONF_MSTR_NOESC, &supvattrs,
        NULL))
        debugx(1, DBG_ERR, "configuration error");
    addrewrite(val, whitelist_mode, whitelist_mode? wlattrs : rmattrs, whitelist_mode? wlvattrs : rmvattrs,
                addattrs, addvattrs, modattrs, modvattrs, supattrs, supvattrs);

    freegconfmstr(whitelist_mode? rmattrs : wlattrs);
    freegconfmstr(whitelist_mode? rmvattrs : wlvattrs);

    return 1;
}

int confrealm_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    char **servers = NULL, **accservers = NULL, **dynauthservers = NULL, *msg = NULL;
    uint8_t accresp = 0;

    debug(DBG_DBG, "confrealm_cb called for %s", block);

    if (!getgenericconfig(cf, block,
			  "server", CONF_MSTR, &servers,
			  "accountingServer", CONF_MSTR, &accservers,
                          "dynAuthServer", CONF_MSTR, &dynauthservers,
			  "ReplyMessage", CONF_STR, &msg,
			  "AccountingResponse", CONF_BLN, &accresp,
			  NULL
	    ))
	debugx(1, DBG_ERR, "configuration error");

    addrealm(realms, val, servers, accservers, dynauthservers, msg, accresp);
    return 1;
}

int setprotoopts(uint8_t type, char **listenargs, char **sourcearg) {
    struct commonprotoopts *protoopts;

    protoopts = malloc(sizeof(struct commonprotoopts));
    if (!protoopts)
	return 0;
    memset(protoopts, 0, sizeof(struct commonprotoopts));
    protoopts->listenargs = listenargs;
    protoopts->sourcearg = sourcearg;
    protodefs[type]->setprotoopts(protoopts);
    return 1;
}

void getmainconfig(const char *configfile) {
    long int addttl = LONG_MIN, loglevel = LONG_MIN;
    struct gconffile *cfs;
    char **listenargs[RAD_PROTOCOUNT];
    char **sourceargs[RAD_PROTOCOUNT];
    char *log_mac_str = NULL;
    char *log_key_str = NULL;
    uint8_t *fticks_reporting_str = NULL;
    uint8_t *fticks_mac_str = NULL;
    uint8_t *fticks_key_str = NULL;
    int i;

    cfs = openconfigfile(configfile);
    memset(&options, 0, sizeof(options));
    memset(&listenargs, 0, sizeof(listenargs));
    memset(&sourceargs, 0, sizeof(sourceargs));
    options.logfullusername = 1;

    clconfs = list_create();
    if (!clconfs)
	debugx(1, DBG_ERR, "malloc failed");

    srvconfs = list_create();
    if (!srvconfs)
	debugx(1, DBG_ERR, "malloc failed");

    realms = list_create();
    if (!realms)
	debugx(1, DBG_ERR, "malloc failed");

    if (!getgenericconfig(
	    &cfs, NULL,
#ifdef RADPROT_UDP
	    "ListenUDP", CONF_MSTR, &listenargs[RAD_UDP],
	    "SourceUDP", CONF_MSTR, &sourceargs[RAD_UDP],
#endif
#ifdef RADPROT_TCP
	    "ListenTCP", CONF_MSTR, &listenargs[RAD_TCP],
	    "SourceTCP", CONF_MSTR, &sourceargs[RAD_TCP],
#endif
#ifdef RADPROT_TLS
	    "ListenTLS", CONF_MSTR, &listenargs[RAD_TLS],
	    "SourceTLS", CONF_MSTR, &sourceargs[RAD_TLS],
#endif
#ifdef RADPROT_DTLS
	    "ListenDTLS", CONF_MSTR, &listenargs[RAD_DTLS],
	    "SourceDTLS", CONF_MSTR, &sourceargs[RAD_DTLS],
#endif
            "PidFile", CONF_STR, &options.pidfile,
	    "TTLAttribute", CONF_STR, &options.ttlattr,
	    "addTTL", CONF_LINT, &addttl,
	    "LogLevel", CONF_LINT, &loglevel,
	    "LogDestination", CONF_STR, &options.logdestination,
        "LogThreadId", CONF_BLN, &options.logtid,
        "LogMAC", CONF_STR, &log_mac_str,
        "LogKey", CONF_STR, &log_key_str,
        "LogFullUsername", CONF_BLN, &options.logfullusername,
	    "LoopPrevention", CONF_BLN, &options.loopprevention,
	    "Client", CONF_CBK, confclient_cb, NULL,
	    "Server", CONF_CBK, confserver_cb, NULL,
	    "Realm", CONF_CBK, confrealm_cb, NULL,
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
	    "TLS", CONF_CBK, conftls_cb, NULL,
#endif
	    "Rewrite", CONF_CBK, confrewrite_cb, NULL,
	    "FTicksReporting", CONF_STR, &fticks_reporting_str,
	    "FTicksMAC", CONF_STR, &fticks_mac_str,
	    "FTicksKey", CONF_STR, &fticks_key_str,
	    "FTicksSyslogFacility", CONF_STR, &options.ftickssyslogfacility,
        "FTicksPrefix", CONF_STR, &options.fticksprefix,
        "IPv4Only", CONF_BLN, &options.ipv4only,
        "IPv6Only", CONF_BLN, &options.ipv6only,
	    NULL
	    ))
	debugx(1, DBG_ERR, "configuration error");

    if (loglevel != LONG_MIN) {
	if (loglevel < 1 || loglevel > 5)
	    debugx(1, DBG_ERR, "error in %s, value of option LogLevel is %d, must be 1, 2, 3, 4 or 5", configfile, loglevel);
	options.loglevel = (uint8_t)loglevel;
    }
    if (log_mac_str != NULL) {
        if (strcasecmp(log_mac_str, "Static") == 0)
            options.log_mac = RSP_MAC_STATIC;
        else if (strcasecmp(log_mac_str, "Original") == 0)
            options.log_mac = RSP_MAC_ORIGINAL;
        else if (strcasecmp(log_mac_str, "VendorHashed") == 0)
            options.log_mac = RSP_MAC_VENDOR_HASHED;
        else if (strcasecmp(log_mac_str, "VendorKeyHashed") == 0)
            options.log_mac = RSP_MAC_VENDOR_KEY_HASHED;
        else if (strcasecmp(log_mac_str, "FullyHashed") == 0)
            options.log_mac = RSP_MAC_FULLY_HASHED;
        else if (strcasecmp(log_mac_str, "FullyKeyHashed") == 0)
            options.log_mac = RSP_MAC_FULLY_KEY_HASHED;
        else {
            debugx(1, DBG_ERR, "config error: invalid LogMAC value: %s", log_mac_str);
        }
        if (log_key_str != NULL) {
            options.log_key = (uint8_t *)log_key_str;
        } else if ((options.log_mac == RSP_MAC_VENDOR_KEY_HASHED
                 || options.log_mac == RSP_MAC_FULLY_KEY_HASHED)) {
            debugx(1, DBG_ERR, "config error: LogMAC %s requires LogKey to be set.", log_mac_str);
        }
        free(log_mac_str);
    } else {
        options.log_mac = RSP_MAC_ORIGINAL;
    }

    if (addttl != LONG_MIN) {
	if (addttl < 1 || addttl > 255)
	    debugx(1, DBG_ERR, "error in %s, value of option addTTL is %d, must be 1-255", configfile, addttl);
	options.addttl = (uint8_t)addttl;
    }
    if (!setttlattr(&options, DEFAULT_TTL_ATTR))
    	debugx(1, DBG_ERR, "Failed to set TTLAttribute, exiting");

    if (!options.fticksprefix)
        options.fticksprefix = DEFAULT_FTICKS_PREFIX;
    fticks_configure(&options, &fticks_reporting_str, &fticks_mac_str,
		     &fticks_key_str);

    for (i = 0; i < RAD_PROTOCOUNT; i++)
	if (listenargs[i] || sourceargs[i])
	    setprotoopts(i, listenargs[i], sourceargs[i]);
}

void getargs(int argc, char **argv, uint8_t *foreground, uint8_t *pretend, uint8_t *loglevel, char **configfile, char **pidfile) {
    int c;

    while ((c = getopt(argc, argv, "c:d:i:fpv")) != -1) {
	switch (c) {
	case 'c':
	    *configfile = optarg;
	    break;
	case 'd':
	    if (strlen(optarg) != 1 || *optarg < '1' || *optarg > '5')
		debugx(1, DBG_ERR, "Debug level must be 1, 2, 3, 4 or 5, not %s", optarg);
	    *loglevel = *optarg - '0';
	    break;
	case 'f':
	    *foreground = 1;
	    break;
	case 'i':
	    *pidfile = optarg;
	    break;
	case 'p':
	    *pretend = 1;
	    break;
	case 'v':
	    debug(DBG_ERR, "radsecproxy revision %s", PACKAGE_VERSION);
	    debug(DBG_ERR, "This binary was built with support for the following transports:");
#ifdef RADPROT_UDP
	    debug(DBG_ERR, "  UDP");
#endif
#ifdef RADPROT_TCP
	    debug(DBG_ERR, "  TCP");
#endif
#ifdef RADPROT_TLS
	    debug(DBG_ERR, "  TLS");
#endif
#ifdef RADPROT_DTLS
	    debug(DBG_ERR, "  DTLS");
#endif
	    exit(0);
	default:
	    goto usage;
	}
    }
    if (!(argc - optind))
	return;

usage:
    debugx(1, DBG_ERR, "Usage:\n%s [ -c configfile ] [ -d debuglevel ] [ -f ] [ -i pidfile ] [ -p ] [ -v ]", argv[0]);
}

#ifdef SYS_SOLARIS9
int daemon(int a, int b) {
    int i;

    if (fork())
	exit(0);

    setsid();

    for (i = 0; i < 3; i++) {
	close(i);
	open("/dev/null", O_RDWR);
    }
    return 1;
}
#endif

void *sighandler(void *arg) {
    sigset_t sigset;
    int sig;

    for(;;) {
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGPIPE);
	sigwait(&sigset, &sig);
        switch (sig) {
        case 0:
            /* completely ignoring this */
            break;
        case SIGHUP:
            debug(DBG_INFO, "sighandler: got SIGHUP");
	    debug_reopen_log();
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
	    tlsreloadcrls();
#endif
            break;
        case SIGPIPE:
            debug(DBG_WARN, "sighandler: got SIGPIPE, TLS write error?");
            break;
        default:
            debug(DBG_WARN, "sighandler: ignoring signal %d", sig);
        }
    }
}

int createpidfile(const char *pidfile) {
    int r = 0;
    FILE *f = fopen(pidfile, "w");
    if (f)
	r = fprintf(f, "%ld\n", (long) getpid());
    return f && !fclose(f) && r >= 0;
}

int radsecproxy_main(int argc, char **argv) {
    pthread_t sigth;
    sigset_t sigset;
    struct list_node *entry;
    uint8_t foreground = 0, pretend = 0, loglevel = 0;
    char *configfile = NULL, *pidfile = NULL;
    struct clsrvconf *srvconf;
    int i;

    debug_init("radsecproxy");
    debug_set_level(DEBUG_LEVEL);

    if (pthread_attr_init(&pthread_attr))
	debugx(1, DBG_ERR, "pthread_attr_init failed");
    if (pthread_attr_setstacksize(&pthread_attr, PTHREAD_STACK_SIZE))
	debugx(1, DBG_ERR, "pthread_attr_setstacksize failed");
#if defined(HAVE_MALLOPT)
    if (mallopt(M_TRIM_THRESHOLD, 4 * 1024) != 1)
	debugx(1, DBG_ERR, "mallopt failed");
#endif

    for (i = 0; i < RAD_PROTOCOUNT; i++)
	protodefs[i] = protoinits[i](i);

    /* needed even if no TLS/DTLS transport */
    randinit();

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
    sslinit();
#endif

    getargs(argc, argv, &foreground, &pretend, &loglevel, &configfile, &pidfile);
    if (loglevel)
	debug_set_level(loglevel);
    getmainconfig(configfile ? configfile : CONFIG_MAIN);
    if (loglevel)
	options.loglevel = loglevel;
    else if (options.loglevel)
	debug_set_level(options.loglevel);
    if (!foreground) {
	debug_set_destination(options.logdestination
                              ? options.logdestination
                              : "x-syslog:///", LOG_TYPE_DEBUG);
    	if (options.ftickssyslogfacility) {
            debug_set_destination(options.ftickssyslogfacility,
                                  LOG_TYPE_FTICKS);
            free(options.ftickssyslogfacility);
    	}
    }
    free(options.logdestination);
    if (options.logtid)
        debug_tid_on();

    if (!list_first(clconfs))
	debugx(1, DBG_ERR, "No clients configured, nothing to do, exiting");
    if (!list_first(realms))
	debugx(1, DBG_ERR, "No realms configured, nothing to do, exiting");

    if (pretend)
	debugx(0, DBG_ERR, "All OK so far; exiting since only pretending");

    if (!foreground && (daemon(0, 0) < 0))
	debugx(1, DBG_ERR, "daemon() failed: %s", strerror(errno));

    debug_timestamp_on();
    debug(DBG_INFO, "radsecproxy %s starting", PACKAGE_VERSION);
    if (!pidfile)
        pidfile = options.pidfile;
    if (pidfile && !createpidfile(pidfile))
	debugx(1, DBG_ERR, "failed to create pidfile %s: %s", pidfile, strerror(errno));

    sigemptyset(&sigset);
    /* exit on all but SIGHUP|SIGPIPE, ignore more? */
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if (pthread_create(&sigth, &pthread_attr, sighandler, NULL))
        debugx(1, DBG_ERR, "pthread_create failed: sighandler");

    for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	srvconf = (struct clsrvconf *)entry->data;
	if (srvconf->dynamiclookupcommand)
	    continue;
	if (!addserver(srvconf))
	    debugx(1, DBG_ERR, "failed to add server");
	if (pthread_create(&srvconf->servers->clientth, &pthread_attr, clientwr,
			   (void *)(srvconf->servers)))
	    debugx(1, DBG_ERR, "pthread_create failed");
    }

    for (i = 0; i < RAD_PROTOCOUNT; i++) {
	if (!protodefs[i])
	    continue;
	if (protodefs[i]->initextra)
	    protodefs[i]->initextra();
        if (find_clconf_type(i, NULL))
	    createlisteners(i);
    }

    /* just hang around doing nothing, anything to do here? */
    for (;;)
	sleep(1000);
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
