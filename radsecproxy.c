/* Copyright (c) 2007-2009, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
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
#include <openssl/md5.h>
#include "debug.h"
#include "hash.h"
#include "util.h"
#include "hostport.h"
#include "radsecproxy.h"
#include "udp.h"
#include "tcp.h"
#include "tls.h"
#include "dtls.h"
#if defined(WANT_FTICKS)
#include "fticks.h"
#endif

static struct options options;
static struct list *clconfs, *srvconfs;
static struct list *realms;
static struct hash *rewriteconfs;

static pthread_mutex_t *ssl_locks = NULL;
static long *ssl_lock_count;
extern int optind;
extern char *optarg;
static const struct protodefs *protodefs[RAD_PROTOCOUNT];

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

/* callbacks for making OpenSSL thread safe */
unsigned long ssl_thread_id() {
    return (unsigned long)pthread_self();
}

void ssl_locking_callback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
	pthread_mutex_lock(&ssl_locks[type]);
	ssl_lock_count[type]++;
    } else
	pthread_mutex_unlock(&ssl_locks[type]);
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
	freerq((struct request *)entry);
    list_destroy(q->entries);
    pthread_cond_destroy(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    free(q);
}

void freebios(struct gqueue *q) {
    BIO *bio;

    pthread_mutex_lock(&q->mutex);
    while ((bio = (BIO *)list_shift(q->entries)))
	BIO_free(bio);
    pthread_mutex_unlock(&q->mutex);
    removequeue(q);
}

struct client *addclient(struct clsrvconf *conf, uint8_t lock) {
    struct client *new = malloc(sizeof(struct client));

    if (!new) {
	debug(DBG_ERR, "malloc failed");
	return NULL;
    }

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

    memset(new, 0, sizeof(struct client));
    new->conf = conf;
    if (conf->pdef->addclient)
	conf->pdef->addclient(new);
    else
	new->replyq = newqueue();
    list_push(conf->clients, new);
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

void removeclientrqs(struct client *client) {
    struct request *rq;
    struct rqout *rqout;
    int i;

    removeclientrqs_sendrq_freeserver_lock(1);
    for (i = 0; i < MAX_REQUESTS; i++) {
	rq = client->rqs[i];
	if (!rq)
	    continue;
	if (rq->to) {
	    rqout = rq->to->requests + rq->newid;
	    pthread_mutex_lock(rqout->lock);
	    if (rqout->rq == rq) /* still pointing to our request */
		freerqoutdata(rqout);
	    pthread_mutex_unlock(rqout->lock);
	}
	freerq(rq);
    }
    removeclientrqs_sendrq_freeserver_lock(0);
}

void removelockedclient(struct client *client) {
    struct clsrvconf *conf;

    conf = client->conf;
    if (conf->clients) {
	removeclientrqs(client);
	removequeue(client->replyq);
	list_removedata(conf->clients, client);
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
	    if (rqout->rq)
		rqout->rq->to = NULL;
	    freerqoutdata(rqout);
	    pthread_mutex_destroy(rqout->lock);
	    free(rqout->lock);
	}
	free(server->requests);
    }
    if (server->rbios)
	freebios(server->rbios);
    free(server->dynamiclookuparg);
    if (server->ssl) {
#if defined ENABLE_EXPERIMENTAL_DYNDISC
        if (server->sock >= 0)
            close(server->sock);
#endif
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

#ifdef RADPROT_DTLS
    if (conf->type == RAD_DTLS)
	conf->servers->rbios = newqueue();
#endif
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
    if (rq)
	rq->refcount++;
    return rq;
}

void freerq(struct request *rq) {
    if (!rq)
	return;
    debug(DBG_DBG, "freerq: called with refcount %d", rq->refcount);
    if (--rq->refcount)
	return;
    if (rq->origusername)
	free(rq->origusername);
    if (rq->buf)
	free(rq->buf);
    if (rq->replybuf)
	free(rq->replybuf);
    if (rq->msg)
	radmsg_free(rq->msg);
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
	freerq(rqout->rq);
	rqout->rq = NULL;
    }
    rqout->tries = 0;
    memset(&rqout->expiry, 0, sizeof(struct timeval));
}

void sendrq(struct request *rq) {
    int i, start;
    struct server *to;

    removeclientrqs_sendrq_freeserver_lock(1);
    to = rq->to;
    if (!to)
	goto errexit;

    start = to->conf->statusserver ? 1 : 0;
    pthread_mutex_lock(&to->newrq_mutex);
    if (start && rq->msg->code == RAD_Status_Server) {
	pthread_mutex_lock(to->requests[0].lock);
	if (to->requests[0].rq) {
	    pthread_mutex_unlock(to->requests[0].lock);
	    debug(DBG_INFO, "sendrq: status server already in queue, dropping request");
	    goto errexit;
	}
	i = 0;
    } else {
	if (!to->nextid)
	    to->nextid = start;
	/* might simplify if only try nextid, might be ok */
	for (i = to->nextid; i < MAX_REQUESTS; i++) {
	    if (!to->requests[i].rq) {
		pthread_mutex_lock(to->requests[i].lock);
		if (!to->requests[i].rq)
		    break;
		pthread_mutex_unlock(to->requests[i].lock);
	    }
	}
	if (i == MAX_REQUESTS) {
	    for (i = start; i < to->nextid; i++) {
		if (!to->requests[i].rq) {
		    pthread_mutex_lock(to->requests[i].lock);
		    if (!to->requests[i].rq)
			break;
		    pthread_mutex_unlock(to->requests[i].lock);
		}
	    }
	    if (i == to->nextid) {
		debug(DBG_INFO, "sendrq: no room in queue, dropping request");
		goto errexit;
	    }
	}
    }
    rq->newid = (uint8_t)i;
    rq->msg->id = (uint8_t)i;
    rq->buf = radmsg2buf(rq->msg, (uint8_t *)to->conf->secret);
    if (!rq->buf) {
	pthread_mutex_unlock(to->requests[i].lock);
	debug(DBG_ERR, "sendrq: radmsg2buf failed");
	goto errexit;
    }

    debug(DBG_DBG, "sendrq: inserting packet with id %d in queue for %s", i, to->conf->name);
    to->requests[i].rq = rq;
    pthread_mutex_unlock(to->requests[i].lock);
    if (i >= start) /* i is not reserved for statusserver */
	to->nextid = i + 1;

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
	rmclientrq(rq, rq->msg->id);
    freerq(rq);
    pthread_mutex_unlock(&to->newrq_mutex);
    removeclientrqs_sendrq_freeserver_lock(0);
}

void sendreply(struct request *rq) {
    uint8_t first;
    struct client *to = rq->from;

    if (!rq->replybuf)
	rq->replybuf = radmsg2buf(rq->msg, (uint8_t *)to->conf->secret);
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

int pwdcrypt(char encrypt_flag, uint8_t *in, uint8_t len, char *shared, uint8_t sharedlen, uint8_t *auth) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE], *input;
    unsigned int md_len;
    uint8_t i, offset = 0, out[128];

    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    input = auth;
    for (;;) {
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, (uint8_t *)shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, input, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
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

int msmppencrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    uint8_t i, offset;

    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

#if 0
    printfchars(NULL, "msppencrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppencrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppencrypt in", "%02x ", text, len);
#endif

    if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	!EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	!EVP_DigestUpdate(&mdctx, auth, 16) ||
	!EVP_DigestUpdate(&mdctx, salt, 2) ||
	!EVP_DigestFinal_ex(&mdctx, hash, &md_len)) {
	pthread_mutex_unlock(&lock);
	return 0;
    }

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
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, text + offset - 16, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
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

int msmppdecrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    uint8_t i, offset;
    char plain[255];

    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

#if 0
    printfchars(NULL, "msppdecrypt auth in", "%02x ", auth, 16);
    printfchars(NULL, "msppdecrypt salt in", "%02x ", salt, 2);
    printfchars(NULL, "msppdecrypt in", "%02x ", text, len);
#endif

    if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	!EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	!EVP_DigestUpdate(&mdctx, auth, 16) ||
	!EVP_DigestUpdate(&mdctx, salt, 2) ||
	!EVP_DigestFinal_ex(&mdctx, hash, &md_len)) {
	pthread_mutex_unlock(&lock);
	return 0;
    }

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
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, text + offset - 16, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
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
    if (r)
	r->refcount++;
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
#if defined ENABLE_EXPERIMENTAL_DYNDISC
        if (((struct clsrvconf *)entry->data)->dynamiclookupcommand
            || ((struct clsrvconf *)entry->data)->servers->in_use)
#else
        if (((struct clsrvconf *)entry->data)->dynamiclookupcommand)
#endif
	    return 1;
    return 0;
}

/* helper function, only used by removeserversubrealms() */
void _internal_removeserversubrealms(struct list *realmlist, struct clsrvconf *srv) {
    struct list_node *entry, *entry2;
    struct realm *realm;

    for (entry = list_first(realmlist); entry;) {
	realm = newrealmref((struct realm *)entry->data);
	pthread_mutex_lock(&realm->mutex);
	entry = list_next(entry);

	if (realm->srvconfs) {
	    for (entry2 = list_first(realm->srvconfs); entry2; entry2 = list_next(entry2))
		if (entry2->data == srv)
		    freerealm(realm);
	    list_removedata(realm->srvconfs, srv);
	}
	if (realm->accsrvconfs) {
	    for (entry2 = list_first(realm->accsrvconfs); entry2; entry2 = list_next(entry2))
		if (entry2->data == srv)
		    freerealm(realm);
	    list_removedata(realm->accsrvconfs, srv);
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

int attrvalidate(unsigned char *attrs, int length) {
    while (length > 1) {
	if (ATTRLEN(attrs) < 2) {
	    debug(DBG_INFO, "attrvalidate: invalid attribute length %d", ATTRLEN(attrs));
	    return 0;
	}
	length -= ATTRLEN(attrs);
	if (length < 0) {
	    debug(DBG_INFO, "attrvalidate: attribute length %d exceeds packet length", ATTRLEN(attrs));
	    return 0;
	}
	attrs += ATTRLEN(attrs);
    }
    if (length)
	debug(DBG_INFO, "attrvalidate: malformed packet? remaining byte after last attribute");
    return 1;
}

int pwdrecrypt(uint8_t *pwd, uint8_t len, char *oldsecret, char *newsecret, uint8_t *oldauth, uint8_t *newauth) {
    if (len < 16 || len > 128 || len % 16) {
	debug(DBG_WARN, "pwdrecrypt: invalid password length");
	return 0;
    }

    if (!pwdcrypt(0, pwd, len, oldsecret, strlen(oldsecret), oldauth)) {
	debug(DBG_WARN, "pwdrecrypt: cannot decrypt password");
	return 0;
    }
#ifdef DEBUG
    printfchars(NULL, "pwdrecrypt: password", "%02x ", pwd, len);
#endif
    if (!pwdcrypt(1, pwd, len, newsecret, strlen(newsecret), newauth)) {
	debug(DBG_WARN, "pwdrecrypt: cannot encrypt password");
	return 0;
    }
    return 1;
}

int msmpprecrypt(uint8_t *msmpp, uint8_t len, char *oldsecret, char *newsecret, uint8_t *oldauth, uint8_t *newauth) {
    if (len < 18)
	return 0;
    if (!msmppdecrypt(msmpp + 2, len - 2, (uint8_t *)oldsecret, strlen(oldsecret), oldauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to decrypt msppe key");
	return 0;
    }
    if (!msmppencrypt(msmpp + 2, len - 2, (uint8_t *)newsecret, strlen(newsecret), newauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to encrypt msppe key");
	return 0;
    }
    return 1;
}

int msmppe(unsigned char *attrs, int length, uint8_t type, char *attrtxt, struct request *rq,
	   char *oldsecret, char *newsecret) {
    unsigned char *attr;

    for (attr = attrs; (attr = attrget(attr, length - (attr - attrs), type)); attr += ATTRLEN(attr)) {
	debug(DBG_DBG, "msmppe: Got %s", attrtxt);
	if (!msmpprecrypt(ATTRVAL(attr), ATTRVALLEN(attr), oldsecret, newsecret, rq->buf + 4, rq->rqauth))
	    return 0;
    }
    return 1;
}

int findvendorsubattr(uint32_t *attrs, uint32_t vendor, uint32_t subattr) {
    if (!attrs)
	return 0;

    for (; attrs[0]; attrs += 2)
	if (attrs[0] == vendor && attrs[1] == subattr)
	    return 1;
    return 0;
}

/* returns 1 if entire element is to be removed, else 0 */
int dovendorrewriterm(struct tlv *attr, uint32_t *removevendorattrs) {
    uint8_t alen, sublen;
    uint32_t vendor;
    uint8_t *subattrs;

    if (!removevendorattrs)
	return 0;

    memcpy(&vendor, attr->v, 4);
    vendor = ntohl(vendor);
    while (*removevendorattrs && *removevendorattrs != vendor)
	removevendorattrs += 2;
    if (!*removevendorattrs)
	return 0;

    if (findvendorsubattr(removevendorattrs, vendor, 256))
	return 1; /* remove entire vendor attribute */

    sublen = attr->l - 4;
    subattrs = attr->v + 4;

    if (!attrvalidate(subattrs, sublen)) {
	debug(DBG_INFO, "dovendorrewrite: vendor attribute validation failed, no rewrite");
	return 0;
    }

    while (sublen > 1) {
	alen = ATTRLEN(subattrs);
	sublen -= alen;
	if (findvendorsubattr(removevendorattrs, vendor, ATTRTYPE(subattrs))) {
	    memmove(subattrs, subattrs + alen, sublen);
	    attr->l -= alen;
	} else
	    subattrs += alen;
    }
    return 0;
}

void dorewriterm(struct radmsg *msg, uint8_t *rmattrs, uint32_t *rmvattrs) {
    struct list_node *n, *p;
    struct tlv *attr;

    p = NULL;
    n = list_first(msg->attrs);
    while (n) {
	attr = (struct tlv *)n->data;
	if ((rmattrs && strchr((char *)rmattrs, attr->t)) ||
	    (rmvattrs && attr->t == RAD_Attr_Vendor_Specific && dovendorrewriterm(attr, rmvattrs))) {
	    list_removedata(msg->attrs, attr);
	    freetlv(attr);
	    n = p ? list_next(p) : list_first(msg->attrs);
	} else {
	    p = n;
	    n = list_next(n);
	}
    }
}

int dorewriteadd(struct radmsg *msg, struct list *addattrs) {
    struct list_node *n;
    struct tlv *a;

    for (n = list_first(addattrs); n; n = list_next(n)) {
	a = copytlv((struct tlv *)n->data);
	if (!a)
	    return 0;
	if (!radmsg_add(msg, a)) {
	    freetlv(a);
	    return 0;
	}
    }
    return 1;
}

int resizeattr(struct tlv *attr, uint8_t newlen) {
    uint8_t *newv;

    if (newlen != attr->l) {
	newv = realloc(attr->v, newlen);
	if (!newv)
	    return 0;
	attr->v = newv;
	attr->l = newlen;
    }
    return 1;
}

int dorewritemodattr(struct tlv *attr, struct modattr *modattr) {
    size_t nmatch = 10, reslen = 0, start = 0;
    regmatch_t pmatch[10], *pfield;
    int i;
    char *in, *out;

    in = stringcopy((char *)attr->v, attr->l);
    if (!in)
	return 0;

    if (regexec(modattr->regex, in, nmatch, pmatch, 0)) {
	free(in);
	return 1;
    }

    out = modattr->replacement;

    for (i = start; out[i]; i++) {
	if (out[i] == '\\' && out[i + 1] >= '1' && out[i + 1] <= '9') {
	    pfield = &pmatch[out[i + 1] - '0'];
	    if (pfield->rm_so >= 0) {
		reslen += i - start + pfield->rm_eo - pfield->rm_so;
		start = i + 2;
	    }
	    i++;
	}
    }
    reslen += i - start;
    if (reslen > 253) {
	debug(DBG_INFO, "rewritten attribute length would be %d, max possible is 253, discarding message", reslen);
	free(in);
	return 0;
    }

    if (!resizeattr(attr, reslen)) {
	free(in);
	return 0;
    }

    start = 0;
    reslen = 0;
    for (i = start; out[i]; i++) {
	if (out[i] == '\\' && out[i + 1] >= '1' && out[i + 1] <= '9') {
	    pfield = &pmatch[out[i + 1] - '0'];
	    if (pfield->rm_so >= 0) {
		memcpy(attr->v + reslen, out + start, i - start);
		reslen += i - start;
		memcpy(attr->v + reslen, in + pfield->rm_so, pfield->rm_eo - pfield->rm_so);
		reslen += pfield->rm_eo - pfield->rm_so;
		start = i + 2;
	    }
	    i++;
	}
    }

    memcpy(attr->v + reslen, out + start, i - start);
    return 1;
}

int dorewritemod(struct radmsg *msg, struct list *modattrs) {
    struct list_node *n, *m;

    for (n = list_first(msg->attrs); n; n = list_next(n))
	for (m = list_first(modattrs); m; m = list_next(m))
	    if (((struct tlv *)n->data)->t == ((struct modattr *)m->data)->t &&
		!dorewritemodattr((struct tlv *)n->data, (struct modattr *)m->data))
		return 0;
    return 1;
}

int dorewrite(struct radmsg *msg, struct rewrite *rewrite) {
    int rv = 1;			/* Success.  */

    if (rewrite) {
	if (rewrite->removeattrs || rewrite->removevendorattrs)
	    dorewriterm(msg, rewrite->removeattrs, rewrite->removevendorattrs);
	if (rewrite->modattrs)
	    if (!dorewritemod(msg, rewrite->modattrs))
		rv = 0;
	if (rewrite->addattrs)
	    if (!dorewriteadd(msg, rewrite->addattrs))
		rv = 0;
    }
    return rv;
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

/** Create vendor specific tlv with ATTR.  ATTR is consumed (freed) if
 * all is well with the new tlv, i.e. if the function returns
 * !NULL.  */
static struct tlv *
makevendortlv(uint32_t vendor, struct tlv *attr)
{
    struct tlv *newtlv = NULL;
    uint8_t l, *v;

    if (!attr)
	return NULL;
    l = attr->l + 6;
    v = malloc(l);
    if (v) {
	vendor = htonl(vendor & 0x00ffffff); /* MSB=0 according to RFC 2865. */
	memcpy(v, &vendor, 4);
	tlv2buf(v + 4, attr);
	v[5] += 2; /* Vendor length increased for type and length fields. */
	newtlv = maketlv(RAD_Attr_Vendor_Specific, l, v);
	if (newtlv == NULL)
	    free(v);
	else
	    freetlv(attr);
    }
    return newtlv;
}

/** Ad vendor attribute with VENDOR + ATTR and push it on MSG.  ATTR
 * is consumed.  */
int addvendorattr(struct radmsg *msg, uint32_t vendor, struct tlv *attr) {
    struct tlv *vattr;

    vattr = makevendortlv(vendor, attr);
    if (!vattr) {
	freetlv(attr);
	return 0;
    }
    if (!radmsg_add(msg, vattr)) {
	freetlv(vattr);
	return 0;
    }
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

void acclog(struct radmsg *msg, struct client *from) {
    struct tlv *attr;
    uint8_t *username;

    attr = radmsg_gettype(msg, RAD_Attr_User_Name);
    if (!attr) {
	debug(DBG_INFO, "acclog: accounting-request from client %s (%s) without username attribute", from->conf->name, addr2string(from->addr));
	return;
    }
    username = radattr2ascii(attr);
    if (username) {
	debug(DBG_INFO, "acclog: accounting-request from client %s (%s) with username: %s", from->conf->name, addr2string(from->addr), username);

	free(username);
    }
}

void respond(struct request *rq, uint8_t code, char *message,
             int copy_proxystate_flag)
{
    struct radmsg *msg;
    struct tlv *attr;

    msg = radmsg_init(code, rq->msg->id, rq->msg->auth);
    if (!msg) {
	debug(DBG_ERR, "respond: malloc failed");
	return;
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
        if (radmsg_copy_attrs(msg, rq->msg, RAD_Proxy_State) < 0) {
            debug(DBG_ERR, "%s: unable to copy all Proxy-State attributes",
                  __func__);
        }
    }

    radmsg_free(rq->msg);
    rq->msg = msg;
    debug(DBG_DBG, "respond: sending %s to %s (%s)", radmsgtype2string(msg->code), rq->from->conf->name, addr2string(rq->from->addr));
    sendreply(newrqref(rq));
}

struct clsrvconf *choosesrvconf(struct list *srvconfs) {
    struct list_node *entry;
    struct clsrvconf *server, *best = NULL, *first = NULL;

    for (entry = list_first(srvconfs); entry; entry = list_next(entry)) {
	server = (struct clsrvconf *)entry->data;
	if (!server->servers)
	    return server;
        if (server->servers->dynfailing)
            continue;
	if (!first)
	    first = server;
	if (!server->servers->connectionok && !server->servers->dynstartup)
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
    return best ? best : first;
}

/* returns with lock on realm, protects from server changes while in use by radsrv/sendrq */
struct server *findserver(struct realm **realm, struct tlv *username, uint8_t acc) {
    struct clsrvconf *srvconf;
    struct realm *subrealm;
    struct server *server = NULL;
    char *id = (char *)tlv2str(username);

    if (!id)
	return NULL;
    /* returns with lock on realm */
    *realm = id2realm(realms, id);
    if (!*realm)
	goto exit;
    debug(DBG_DBG, "found matching realm: %s", (*realm)->name);
    srvconf = choosesrvconf(acc ? (*realm)->accsrvconfs : (*realm)->srvconfs);
    if (srvconf && !(*realm)->parent && !srvconf->servers && srvconf->dynamiclookupcommand) {
	subrealm = adddynamicrealmserver(*realm, id);
	if (subrealm) {
	    pthread_mutex_lock(&subrealm->mutex);
	    pthread_mutex_unlock(&(*realm)->mutex);
	    freerealm(*realm);
	    *realm = subrealm;
            debug(DBG_DBG, "added realm: %s", (*realm)->name);
	    srvconf = choosesrvconf(acc ? (*realm)->accsrvconfs : (*realm)->srvconfs);
            debug(DBG_DBG, "found conf for new realm: %s", srvconf->name);
	}
    }
    if (srvconf) {
        debug(DBG_DBG, "found matching conf: %s", srvconf->name);
	server = srvconf->servers;
    }

exit:
    free(id);
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
	    freerq(r);
	    client->rqs[i] = NULL;
	}
    }
}

int addclientrq(struct request *rq) {
    struct request *r;
    struct timeval now;

    r = rq->from->rqs[rq->rqid];
    if (r) {
	if (rq->udpport == r->udpport && !memcmp(rq->rqauth, r->rqauth, 16)) {
	    gettimeofday(&now, NULL);
	    if (now.tv_sec - r->created.tv_sec < r->from->conf->dupinterval) {
		if (r->replybuf) {
		    debug(DBG_INFO, "addclientrq: already sent reply to request with id %d from %s, resending", rq->rqid, addr2string(r->from->addr));
		    sendreply(newrqref(r));
		} else
		    debug(DBG_INFO, "addclientrq: already got request with id %d from %s, ignoring", rq->rqid, addr2string(r->from->addr));
		return 0;
	    }
	}
	freerq(r);
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

/* returns 0 if validation/authentication fails, else 1 */
int radsrv(struct request *rq) {
    struct radmsg *msg = NULL;
    struct tlv *attr;
    uint8_t *userascii = NULL;
    struct realm *realm = NULL;
    struct server *to = NULL;
    struct client *from = rq->from;
    int ttlres;

    msg = buf2radmsg(rq->buf, (uint8_t *)from->conf->secret, NULL);
    free(rq->buf);
    rq->buf = NULL;

    if (!msg) {
	debug(DBG_INFO, "radsrv: message validation failed, ignoring packet");
	freerq(rq);
	return 0;
    }

    rq->msg = msg;
    rq->rqid = msg->id;
    memcpy(rq->rqauth, msg->auth, 16);

    debug(DBG_DBG, "radsrv: code %d, id %d", msg->code, msg->id);
    if (msg->code != RAD_Access_Request && msg->code != RAD_Status_Server && msg->code != RAD_Accounting_Request) {
	debug(DBG_INFO, "radsrv: server currently accepts only access-requests, accounting-requests and status-server, ignoring");
	goto exit;
    }

    purgedupcache(from);
    if (!addclientrq(rq))
	goto exit;

    if (msg->code == RAD_Status_Server) {
	respond(rq, RAD_Access_Accept, NULL, 0);
	goto exit;
    }

    /* below: code == RAD_Access_Request || code == RAD_Accounting_Request */

    if (from->conf->rewritein && !dorewrite(msg, from->conf->rewritein))
	goto rmclrqexit;

    ttlres = checkttl(msg, options.ttlattrtype);
    if (!ttlres) {
	debug(DBG_INFO, "radsrv: ignoring request from client %s (%s), ttl exceeded", from->conf->name, addr2string(from->addr));
	goto exit;
    }

    attr = radmsg_gettype(msg, RAD_Attr_User_Name);
    if (!attr) {
	if (msg->code == RAD_Accounting_Request) {
	    acclog(msg, from);
	    respond(rq, RAD_Accounting_Response, NULL, 1);
	} else
	    debug(DBG_INFO, "radsrv: ignoring access request, no username attribute");
	goto exit;
    }

    if (from->conf->rewriteusername && !rewriteusername(rq, attr)) {
	debug(DBG_WARN, "radsrv: username malloc failed, ignoring request");
	goto rmclrqexit;
    }

    userascii = radattr2ascii(attr);
    if (!userascii)
	goto rmclrqexit;
    debug(DBG_DBG, "%s with username: %s", radmsgtype2string(msg->code), userascii);

    /* will return with lock on the realm */
    to = findserver(&realm, attr, msg->code == RAD_Accounting_Request);
    if (!realm) {
	debug(DBG_INFO, "radsrv: ignoring request, don't know where to send it");
	goto exit;
    }

    if (!to) {
	if (realm->message && msg->code == RAD_Access_Request) {
	    debug(DBG_INFO, "radsrv: sending reject to %s (%s) for %s", from->conf->name, addr2string(from->addr), userascii);
	    respond(rq, RAD_Access_Reject, realm->message, 1);
	} else if (realm->accresp && msg->code == RAD_Accounting_Request) {
	    acclog(msg, from);
	    respond(rq, RAD_Accounting_Response, NULL, 1);
	}
	goto exit;
    }

    if ((to->conf->loopprevention == 1
	 || (to->conf->loopprevention == UCHAR_MAX && options.loopprevention == 1))
	&& !strcmp(from->conf->name, to->conf->name)) {
	debug(DBG_INFO, "radsrv: Loop prevented, not forwarding request from client %s (%s) to server %s, discarding",
	      from->conf->name, addr2string(from->addr), to->conf->name);
	goto exit;
    }

    if (msg->code == RAD_Accounting_Request)
	memset(msg->auth, 0, 16);
    else if (!RAND_bytes(msg->auth, 16)) {
	debug(DBG_WARN, "radsrv: failed to generate random auth");
	goto rmclrqexit;
    }

#ifdef DEBUG
    printfchars(NULL, "auth", "%02x ", auth, 16);
#endif

    attr = radmsg_gettype(msg, RAD_Attr_User_Password);
    if (attr) {
	debug(DBG_DBG, "radsrv: found userpwdattr with value length %d", attr->l);
	if (!pwdrecrypt(attr->v, attr->l, from->conf->secret, to->conf->secret, rq->rqauth, msg->auth))
	    goto rmclrqexit;
    }

    attr = radmsg_gettype(msg, RAD_Attr_Tunnel_Password);
    if (attr) {
	debug(DBG_DBG, "radsrv: found tunnelpwdattr with value length %d", attr->l);
	if (!pwdrecrypt(attr->v, attr->l, from->conf->secret, to->conf->secret, rq->rqauth, msg->auth))
	    goto rmclrqexit;
    }

    if (to->conf->rewriteout && !dorewrite(msg, to->conf->rewriteout))
	goto rmclrqexit;

    if (ttlres == -1 && (options.addttl || to->conf->addttl))
	addttlattr(msg, options.ttlattrtype, to->conf->addttl ? to->conf->addttl : options.addttl);

    free(userascii);
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
    if (realm) {
	pthread_mutex_unlock(&realm->mutex);
	freerealm(realm);
    }
    return 1;
}

void replyh(struct server *server, unsigned char *buf) {
    struct client *from;
    struct rqout *rqout;
    int sublen, ttlres;
    unsigned char *subattrs;
    uint8_t *username, *stationid, *replymsg;
    struct radmsg *msg = NULL;
    struct tlv *attr;
    struct list_node *node;

    server->connectionok = 1;
    server->lostrqs = 0;

    rqout = server->requests + buf[1];
    pthread_mutex_lock(rqout->lock);
    if (!rqout->tries) {
	free(buf);
	buf = NULL;
	debug(DBG_INFO, "replyh: no outstanding request with this id, ignoring reply");
	goto errunlock;
    }

    msg = buf2radmsg(buf, (uint8_t *)server->conf->secret, rqout->rq->msg->auth);
    free(buf);
    buf = NULL;
    if (!msg) {
        debug(DBG_INFO, "replyh: message validation failed, ignoring packet");
	goto errunlock;
    }
    if (msg->code != RAD_Access_Accept && msg->code != RAD_Access_Reject && msg->code != RAD_Access_Challenge
	&& msg->code != RAD_Accounting_Response) {
	debug(DBG_INFO, "replyh: discarding message type %s, accepting only access accept, access reject, access challenge and accounting response messages", radmsgtype2string(msg->code));
	goto errunlock;
    }
    debug(DBG_DBG, "got %s message with id %d", radmsgtype2string(msg->code), msg->id);

    gettimeofday(&server->lastrcv, NULL);

    if (rqout->rq->msg->code == RAD_Status_Server) {
	freerqoutdata(rqout);
	debug(DBG_DBG, "replyh: got status server response from %s", server->conf->name);
	goto errunlock;
    }

    gettimeofday(&server->lastreply, NULL);
    from = rqout->rq->from;

    if (server->conf->rewritein && !dorewrite(msg, from->conf->rewritein)) {
	debug(DBG_INFO, "replyh: rewritein failed");
	goto errunlock;
    }

    ttlres = checkttl(msg, options.ttlattrtype);
    if (!ttlres) {
	debug(DBG_INFO, "replyh: ignoring reply from server %s, ttl exceeded", server->conf->name);
	goto errunlock;
    }

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
		    rqout->rq, server->conf->secret, from->conf->secret) ||
	    !msmppe(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Recv_Key, "MS MPPE Recv Key",
		    rqout->rq, server->conf->secret, from->conf->secret))
	    break;
    }
    if (node) {
	debug(DBG_WARN, "replyh: MS attribute handling failed, ignoring reply");
	goto errunlock;
    }

    if (msg->code == RAD_Access_Accept || msg->code == RAD_Access_Reject || msg->code == RAD_Accounting_Response) {
	username = radattr2ascii(radmsg_gettype(rqout->rq->msg, RAD_Attr_User_Name));
	if (username) {
	    stationid = radattr2ascii(radmsg_gettype(rqout->rq->msg, RAD_Attr_Calling_Station_Id));
	    replymsg = radattr2ascii(radmsg_gettype(msg, RAD_Attr_Reply_Message));
	    if (stationid) {
		if (replymsg) {
		    debug(DBG_NOTICE,
			  "%s for user %s stationid %s from %s (%s) to %s (%s)",
			  radmsgtype2string(msg->code), username, stationid,
			  server->conf->name, replymsg, from->conf->name,
			  addr2string(from->addr));
		    free(replymsg);
		} else
		    debug(DBG_NOTICE,
			  "%s for user %s stationid %s from %s to %s (%s)",
			  radmsgtype2string(msg->code), username, stationid,
			  server->conf->name, from->conf->name,
			  addr2string(from->addr));
		free(stationid);
	    } else {
		if (replymsg) {
		    debug(DBG_NOTICE, "%s for user %s from %s (%s) to %s (%s)",
			  radmsgtype2string(msg->code), username,
			  server->conf->name, replymsg, from->conf->name,
			  addr2string(from->addr));
		    free(replymsg);
		} else
		    debug(DBG_NOTICE, "%s for user %s from %s to %s (%s)",
			  radmsgtype2string(msg->code), username,
			  server->conf->name, from->conf->name,
			  addr2string(from->addr));
	    }
	    free(username);
	}
    }

#if defined(WANT_FTICKS)
    if (msg->code == RAD_Access_Accept || msg->code == RAD_Access_Reject)
	if (options.fticks_reporting && from->conf->fticks_viscountry != NULL)
	    fticks_log(&options, from, msg, rqout);
#endif

    msg->id = (char)rqout->rq->rqid;
    memcpy(msg->auth, rqout->rq->rqauth, 16);

#ifdef DEBUG
    printfchars(NULL, "origauth/buf+4", "%02x ", buf + 4, 16);
#endif

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

    debug(msg->code == RAD_Access_Accept || msg->code == RAD_Access_Reject || msg->code == RAD_Accounting_Response ? DBG_WARN : DBG_INFO,
	  "replyh: passing %s to client %s (%s)", radmsgtype2string(msg->code), from->conf->name, addr2string(from->addr));

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
    uint8_t rnd;
    struct timeval now, laststatsrv;
    struct timespec timeout;
    struct request *statsrvrq;
    struct clsrvconf *conf;

    conf = server->conf;

#define ZZZ 900

    if (server->dynamiclookuparg && !dynamicconfig(server)) {
	dynconffail = 1;
	server->dynstartup = 0;
	server->dynfailing = 1;
#if defined ENABLE_EXPERIMENTAL_DYNDISC
	pthread_mutex_unlock(&server->lock);
#endif
	debug(DBG_WARN, "%s: dynamicconfig(%s: %s) failed, sleeping %ds",
              __func__, server->conf->name, server->dynamiclookuparg, ZZZ);
	sleep(ZZZ);
	goto errexit;
    }
#if defined ENABLE_EXPERIMENTAL_DYNDISC
    pthread_mutex_unlock(&server->lock);
#endif
    /* FIXME: Is resolving not always done by compileserverconfig(),
     * either as part of static configuration setup or by
     * dynamicconfig() above?  */
    if (!resolvehostports(conf->hostports, conf->hostaf, conf->pdef->socktype)) {
        debug(DBG_WARN, "%s: resolve failed, sleeping %ds", __func__, ZZZ);
        sleep(ZZZ);
        goto errexit;
    }

    memset(&timeout, 0, sizeof(struct timespec));

    if (conf->statusserver) {
	gettimeofday(&server->lastrcv, NULL);
	gettimeofday(&laststatsrv, NULL);
    }

    if (conf->pdef->connecter) {
	if (!conf->pdef->connecter(server, NULL, server->dynamiclookuparg ? 5 : 0, "clientwr")) {
	    if (server->dynamiclookuparg) {
                server->dynstartup = 0;
		server->dynfailing = 1;
                debug(DBG_WARN, "%s: connect failed, sleeping %ds",
                      __func__, ZZZ);
		sleep(ZZZ);
	    }
	    goto errexit;
	}
	server->connectionok = 1;
#if defined ENABLE_EXPERIMENTAL_DYNDISC
	server->in_use = 1;
#endif
	if (pthread_create(&clientrdth, &pthread_attr, conf->pdef->clientconnreader, (void *)server)) {
	    debugerrno(errno, DBG_ERR, "clientwr: pthread_create failed");
	    goto errexit;
	}
    } else
	server->connectionok = 1;
    server->dynstartup = 0;

    for (;;) {
	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->newrq) {
	    gettimeofday(&now, NULL);
	    /* random 0-7 seconds */
	    RAND_bytes(&rnd, 1);
	    rnd /= 32;
	    if (conf->statusserver) {
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
#if 0
	else
	    debug(DBG_DBG, "clientwr: request timer expired, processing request queue");
#endif
	pthread_mutex_unlock(&server->newrq_mutex);

	for (i = 0; i < MAX_REQUESTS; i++) {
	    if (server->clientrdgone) {
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
            if (now.tv_sec < rqout->expiry.tv_sec) {
		if (!timeout.tv_sec || rqout->expiry.tv_sec < timeout.tv_sec)
		    timeout.tv_sec = rqout->expiry.tv_sec;
                pthread_mutex_unlock(rqout->lock);
		continue;
	    }

	    if (rqout->tries == (*rqout->rq->buf == RAD_Status_Server ? 1 : conf->retrycount + 1)) {
		debug(DBG_DBG, "clientwr: removing expired packet from queue");
		if (conf->statusserver) {
		    if (*rqout->rq->buf == RAD_Status_Server) {
			debug(DBG_WARN, "clientwr: no status server response, %s dead?", conf->name);
			if (server->lostrqs < 255)
			    server->lostrqs++;
		    }
                } else {
		    debug(DBG_WARN, "clientwr: no server response, %s dead?", conf->name);
		    if (server->lostrqs < 255)
			server->lostrqs++;
		}
		freerqoutdata(rqout);
                pthread_mutex_unlock(rqout->lock);
		continue;
	    }

	    rqout->expiry.tv_sec = now.tv_sec + conf->retryinterval;
	    if (!timeout.tv_sec || rqout->expiry.tv_sec < timeout.tv_sec)
		timeout.tv_sec = rqout->expiry.tv_sec;
	    rqout->tries++;
	    conf->pdef->clientradput(server, rqout->rq->buf);
	    pthread_mutex_unlock(rqout->lock);
	}
	if (conf->statusserver && server->connectionok) {
	    secs = server->lastrcv.tv_sec > laststatsrv.tv_sec ? server->lastrcv.tv_sec : laststatsrv.tv_sec;
	    gettimeofday(&now, NULL);
	    if (now.tv_sec - secs > STATUS_SERVER_PERIOD) {
		laststatsrv = now;
		statsrvrq = createstatsrvrq();
		if (statsrvrq) {
		    statsrvrq->to = server;
		    debug(DBG_DBG, "clientwr: sending status server to %s", conf->name);
		    sendrq(statsrvrq);
		}
	    }
	}
    }
errexit:
#if defined ENABLE_EXPERIMENTAL_DYNDISC
    server->in_use = 0;
#endif
    conf->servers = NULL;
    if (server->dynamiclookuparg) {
	removeserversubrealms(realms, conf);
	if (dynconffail)
	    free(conf);
	else
	    freeclsrvconf(conf);
    }
    freeserver(server, 1);
    ERR_remove_state(0);
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
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	disable_DF_bit(s, res);

#ifdef IPV6_V6ONLY
	if (res->ai_family == AF_INET6)
	    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
	if (bind(s, res->ai_addr, res->ai_addrlen)) {
	    debugerrno(errno, DBG_WARN, "createlistener: bind failed");
	    close(s);
	    s = -1;
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

void sslinit() {
    int i;
    time_t t;
    pid_t pid;

    ssl_locks = calloc(CRYPTO_num_locks(), sizeof(pthread_mutex_t));
    ssl_lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
	ssl_lock_count[i] = 0;
	pthread_mutex_init(&ssl_locks[i], NULL);
    }
    CRYPTO_set_id_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_locking_callback);

    SSL_load_error_strings();
    SSL_library_init();

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
	    list_destroy(conflist);
	    return NULL;
	}
	if (!list_push(conflist, conf)) {
	    debug(DBG_ERR, "malloc failed");
	    list_destroy(conflist);
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
    if (--realm->refcount)
	return;

    free(realm->name);
    free(realm->message);
    regfree(&realm->regex);
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

struct realm *addrealm(struct list *realmlist, char *value, char **servers, char **accservers, char *message, uint8_t accresp) {
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

    if (pthread_mutex_init(&realm->mutex, NULL)) {
	debugerrno(errno, DBG_ERR, "mutex init failed");
	free(realm);
	realm = NULL;
	goto exit;
    }

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
    return newrealmref(realm);
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
		srvconf->servers->dynstartup = 1;
                debug(DBG_DBG, "%s: new client writer for %s",
                      __func__, srvconf->servers->conf->name);
#if defined ENABLE_EXPERIMENTAL_DYNDISC
        	pthread_mutex_lock(&srvconf->servers->lock);
#endif
		if (pthread_create(&clientth, &pthread_attr, clientwr, (void *)(srvconf->servers))) {
#if defined ENABLE_EXPERIMENTAL_DYNDISC
                    pthread_mutex_unlock(&srvconf->servers->lock);
#endif
		    debugerrno(errno, DBG_ERR, "pthread_create failed");
		    freeserver(srvconf->servers, 1);
		    srvconf->servers = NULL;
#if defined ENABLE_EXPERIMENTAL_DYNDISC
		    conf = srvconf;
		    continue;
#endif
		} else
		    pthread_detach(clientth);

#if defined ENABLE_EXPERIMENTAL_DYNDISC
                /* If clientwr() could not find a NAPTR we have to
                 * wait for dynfailing=1 what is set in clientwr().  */
                pthread_mutex_lock(&srvconf->servers->lock);
                pthread_mutex_unlock(&srvconf->servers->lock);
#endif
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

    newrealm = addrealm(realm->subrealms, realmname, NULL, NULL, stringcopy(realm->message, 0), realm->accresp);
    if (!newrealm) {
	list_destroy(realm->subrealms);
	realm->subrealms = NULL;
	return NULL;
    }

    newrealm->parent = newrealmref(realm);
    /* add server and accserver to newrealm */
    newrealm->srvconfs = createsubrealmservers(newrealm, realm->srvconfs);
    newrealm->accsrvconfs = createsubrealmservers(newrealm, realm->accsrvconfs);
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

/* should accept both names and numeric values, only numeric right now */
uint8_t attrname2val(char *attrname) {
    int val = 0;

    val = atoi(attrname);
    return val > 0 && val < 256 ? val : 0;
}

/* ATTRNAME is on the form vendor[:type].
   If only vendor is found, TYPE is set to 256 and 1 is returned.
   If type is >= 256, 1 is returned.
   Otherwise, 0 is returned.
*/
/* should accept both names and numeric values, only numeric right now */
int vattrname2val(char *attrname, uint32_t *vendor, uint32_t *type) {
    char *s;

    *vendor = atoi(attrname);
    s = strchr(attrname, ':');
    if (!s) {			/* Only vendor was found.  */
	*type = 256;
	return 1;
    }
    *type = atoi(s + 1);
    return *type < 256;
}

/** Extract attributes from string NAMEVAL, create a struct tlv and
 * return the tlv.  If VENDOR_FLAG, NAMEVAL is on the form
 * "<vendor>:<name>:<val>" and otherwise it's "<name>:<val>".  Return
 * NULL if fields are missing or if conversion fails.
 *
 * FIXME: Should accept both names and numeric values, only numeric
 * right now */
struct tlv *extractattr(char *nameval, char vendor_flag) {
    int len, name = 0;
    int vendor = 0;	    /* Vendor 0 is reserved, see RFC 1700.  */
    char *s, *s2;
    struct tlv *a;

    s = strchr(nameval, ':');
    if (!s)
	return NULL;
    name = atoi(nameval);

    if (vendor_flag) {
	s2 = strchr(s + 1, ':');
	if (!s2)
	    return NULL;
	vendor = name;
	name = atoi(s + 1);
	s = s2;
    }
    len = strlen(s + 1);
    if (len > 253)
	return NULL;

    if (name < 1 || name > 255)
	return NULL;
    a = malloc(sizeof(struct tlv));
    if (!a)
	return NULL;

    a->v = (uint8_t *)stringcopy(s + 1, 0);
    if (!a->v) {
	free(a);
	return NULL;
    }
    a->t = name;
    a->l = len;

    if (vendor_flag)
 	a = makevendortlv(vendor, a);

    return a;
}

/* should accept both names and numeric values, only numeric right now */
struct modattr *extractmodattr(char *nameval) {
    int name = 0;
    char *s, *t;
    struct modattr *m;

    if (!strncasecmp(nameval, "User-Name:/", 11)) {
	s = nameval + 11;
	name = 1;
    } else {
	s = strchr(nameval, ':');
	name = atoi(nameval);
	if (!s || name < 1 || name > 255 || s[1] != '/')
	    return NULL;
	s += 2;
    }
    /* regexp, remove optional trailing / if present */
    if (s[strlen(s) - 1] == '/')
	s[strlen(s) - 1] = '\0';

    for (t = strchr(s, '/'); t; t = strchr(t+1, '/'))
        if (t == s || t[-1] != '\\')
            break;
    if (!t)
	return NULL;
    *t = '\0';
    t++;

    m = malloc(sizeof(struct modattr));
    if (!m) {
	debug(DBG_ERR, "malloc failed");
	return NULL;
    }
    m->t = name;

    m->replacement = stringcopy(t, 0);
    if (!m->replacement) {
	free(m);
	debug(DBG_ERR, "malloc failed");
	return NULL;
    }

    m->regex = malloc(sizeof(regex_t));
    if (!m->regex) {
	free(m->replacement);
	free(m);
	debug(DBG_ERR, "malloc failed");
	return NULL;
    }

    if (regcomp(m->regex, s, REG_ICASE | REG_EXTENDED)) {
	free(m->regex);
	free(m->replacement);
	free(m);
	debug(DBG_ERR, "failed to compile regular expression %s", s);
	return NULL;
    }

    return m;
}

struct rewrite *getrewrite(char *alt1, char *alt2) {
    struct rewrite *r;

    if (alt1)
	if ((r = hash_read(rewriteconfs,  alt1, strlen(alt1))))
	    return r;
    if (alt2)
	if ((r = hash_read(rewriteconfs,  alt2, strlen(alt2))))
	    return r;
    return NULL;
}

void addrewrite(char *value, char **rmattrs, char **rmvattrs, char **addattrs, char **addvattrs, char **modattrs)
{
    struct rewrite *rewrite = NULL;
    int i, n;
    uint8_t *rma = NULL;
    uint32_t *p, *rmva = NULL;
    struct list *adda = NULL, *moda = NULL;
    struct tlv *a;
    struct modattr *m;

    if (rmattrs) {
	for (n = 0; rmattrs[n]; n++);
	rma = calloc(n + 1, sizeof(uint8_t));
	if (!rma)
	    debugx(1, DBG_ERR, "malloc failed");

	for (i = 0; i < n; i++)
	    if (!(rma[i] = attrname2val(rmattrs[i])))
		debugx(1, DBG_ERR, "addrewrite: removing invalid attribute %s", rmattrs[i]);
	freegconfmstr(rmattrs);
	rma[i] = 0;
    }

    if (rmvattrs) {
	for (n = 0; rmvattrs[n]; n++);
	rmva = calloc(2 * n + 1, sizeof(uint32_t));
	if (!rmva)
	    debugx(1, DBG_ERR, "malloc failed");

	for (p = rmva, i = 0; i < n; i++, p += 2)
	    if (!vattrname2val(rmvattrs[i], p, p + 1))
		debugx(1, DBG_ERR, "addrewrite: removing invalid vendor attribute %s", rmvattrs[i]);
	freegconfmstr(rmvattrs);
	*p = 0;
    }

    if (addattrs) {
	adda = list_create();
	if (!adda)
	    debugx(1, DBG_ERR, "malloc failed");
	for (i = 0; addattrs[i]; i++) {
	    a = extractattr(addattrs[i], 0);
	    if (!a)
		debugx(1, DBG_ERR, "addrewrite: adding invalid attribute %s", addattrs[i]);
	    if (!list_push(adda, a))
		debugx(1, DBG_ERR, "malloc failed");
	}
	freegconfmstr(addattrs);
    }

    if (addvattrs) {
	if (!adda)
	    adda = list_create();
	if (!adda)
	    debugx(1, DBG_ERR, "malloc failed");
	for (i = 0; addvattrs[i]; i++) {
	    a = extractattr(addvattrs[i], 1);
	    if (!a)
		debugx(1, DBG_ERR, "addrewrite: adding invalid vendor attribute %s", addvattrs[i]);
	    if (!list_push(adda, a))
		debugx(1, DBG_ERR, "malloc failed");
	}
	freegconfmstr(addvattrs);
    }

    if (modattrs) {
	moda = list_create();
	if (!moda)
	    debugx(1, DBG_ERR, "malloc failed");
	for (i = 0; modattrs[i]; i++) {
	    m = extractmodattr(modattrs[i]);
	    if (!m)
		debugx(1, DBG_ERR, "addrewrite: modifying invalid attribute %s", modattrs[i]);
	    if (!list_push(moda, m))
		debugx(1, DBG_ERR, "malloc failed");
	}
	freegconfmstr(modattrs);
    }

    if (rma || rmva || adda || moda) {
	rewrite = malloc(sizeof(struct rewrite));
	if (!rewrite)
	    debugx(1, DBG_ERR, "malloc failed");
	rewrite->removeattrs = rma;
	rewrite->removevendorattrs = rmva;
	rewrite->addattrs = adda;
	rewrite->modattrs = moda;
    }

    if (!hash_insert(rewriteconfs, value, strlen(value), rewrite))
	debugx(1, DBG_ERR, "malloc failed");
    debug(DBG_DBG, "addrewrite: added rewrite block %s", value);
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
    assert(conf->name);
    debug(DBG_DBG, "%s: freeing %p (%s)", __func__, conf, conf->name);
    free(conf->name);
    if (conf->hostsrc)
	freegconfmstr(conf->hostsrc);
    free(conf->portsrc);
    free(conf->secret);
    free(conf->tls);
    free(conf->matchcertattr);
    if (conf->certcnregex)
	regfree(conf->certcnregex);
    if (conf->certuriregex)
	regfree(conf->certuriregex);
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
	!mergeconfstring(&dst->secret, &src->secret) ||
	!mergeconfstring(&dst->tls, &src->tls) ||
	!mergeconfstring(&dst->matchcertattr, &src->matchcertattr) ||
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
    struct clsrvconf *conf;
    char *conftype = NULL, *rewriteinalias = NULL;
    long int dupinterval = LONG_MIN, addttl = LONG_MIN;
    uint8_t ipv4only = 0, ipv6only = 0;

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
	    "secret", CONF_STR, &conf->secret,
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
	    "tls", CONF_STR, &conf->tls,
	    "matchcertificateattribute", CONF_STR, &conf->matchcertattr,
	    "CertificateNameCheck", CONF_BLN, &conf->certnamecheck,
#endif
	    "DuplicateInterval", CONF_LINT, &dupinterval,
	    "addTTL", CONF_LINT, &addttl,
	    "rewrite", CONF_STR, &rewriteinalias,
	    "rewriteIn", CONF_STR, &conf->confrewritein,
	    "rewriteOut", CONF_STR, &conf->confrewriteout,
	    "rewriteattribute", CONF_STR, &conf->confrewriteusername,
#if defined(WANT_FTICKS)
	    "fticksVISCOUNTRY", CONF_STR, &conf->fticks_viscountry,
	    "fticksVISINST", CONF_STR, &conf->fticks_visinst,
#endif
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
	if (conf->matchcertattr && !addmatchcertattr(conf))
	    debugx(1, DBG_ERR, "error in block %s, invalid MatchCertificateAttributeValue", block);
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

    if (!conf->secret) {
	if (!conf->pdef->secretdefault)
	    debugx(1, DBG_ERR, "error in block %s, secret must be specified for transport type %s", block, conf->pdef->name);
	conf->secret = stringcopy(conf->pdef->secretdefault, 0);
	if (!conf->secret)
	    debugx(1, DBG_ERR, "malloc failed");
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
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
    if (conf->type == RAD_TLS || conf->type == RAD_DTLS) {
    	conf->tlsconf = conf->tls
            ? tlsgettls(conf->tls, NULL)
            : tlsgettls("defaultServer", "default");
	if (!conf->tlsconf) {
	    debug(DBG_ERR, "error in block %s, no tls context defined", block);
	    return 0;
	}
	if (conf->matchcertattr && !addmatchcertattr(conf)) {
	    debug(DBG_ERR, "error in block %s, invalid MatchCertificateAttributeValue", block);
	    return 0;
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
    char *conftype = NULL, *rewriteinalias = NULL;
    long int retryinterval = LONG_MIN, retrycount = LONG_MIN, addttl = LONG_MIN;
    uint8_t ipv4only = 0, ipv6only = 0;

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
    } else
	conf->certnamecheck = 1;

    if (!getgenericconfig(cf, block,
			  "type", CONF_STR, &conftype,
			  "host", CONF_MSTR, &conf->hostsrc,
                          "IPv4Only", CONF_BLN, &ipv4only,
                          "IPv6Only", CONF_BLN, &ipv6only,
			  "port", CONF_STR, &conf->portsrc,
			  "secret", CONF_STR, &conf->secret,
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
			  "tls", CONF_STR, &conf->tls,
			  "MatchCertificateAttribute", CONF_STR, &conf->matchcertattr,
			  "CertificateNameCheck", CONF_BLN, &conf->certnamecheck,
#endif
			  "addTTL", CONF_LINT, &addttl,
			  "rewrite", CONF_STR, &rewriteinalias,
			  "rewriteIn", CONF_STR, &conf->confrewritein,
			  "rewriteOut", CONF_STR, &conf->confrewriteout,
			  "StatusServer", CONF_BLN, &conf->statusserver,
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

    if (resconf) {
	if (!mergesrvconf(resconf, conf))
	    goto errexit;
	free(conf);
	conf = resconf;
	if (conf->dynamiclookupcommand) {
	    free(conf->dynamiclookupcommand);
	    conf->dynamiclookupcommand = NULL;
	}
    }

    if (resconf || !conf->dynamiclookupcommand) {
	if (!compileserverconfig(conf, block))
            return 0; /* Don't goto errexit and free resconf -- it's
                       * not ours to free.  */
    }

    if (!conf->secret) {
	if (!conf->pdef->secretdefault) {
	    debug(DBG_ERR, "error in block %s, secret must be specified for transport type %s", block, conf->pdef->name);
	    return 0;
	}
	conf->secret = stringcopy(conf->pdef->secretdefault, 0);
	if (!conf->secret) {
	    debug(DBG_ERR, "malloc failed");
	    return 0;
	}
    }

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
    freeclsrvconf(conf);
    return 0;
}

int confrealm_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    char **servers = NULL, **accservers = NULL, *msg = NULL;
    uint8_t accresp = 0;

    debug(DBG_DBG, "confrealm_cb called for %s", block);

    if (!getgenericconfig(cf, block,
			  "server", CONF_MSTR, &servers,
			  "accountingServer", CONF_MSTR, &accservers,
			  "ReplyMessage", CONF_STR, &msg,
			  "AccountingResponse", CONF_BLN, &accresp,
			  NULL
	    ))
	debugx(1, DBG_ERR, "configuration error");

    addrealm(realms, val, servers, accservers, msg, accresp);
    return 1;
}

int confrewrite_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val) {
    char **rmattrs = NULL, **rmvattrs = NULL;
    char **addattrs = NULL, **addvattrs = NULL;
    char **modattrs = NULL;

    debug(DBG_DBG, "confrewrite_cb called for %s", block);

    if (!getgenericconfig(cf, block,
			  "removeAttribute", CONF_MSTR, &rmattrs,
			  "removeVendorAttribute", CONF_MSTR, &rmvattrs,
			  "addAttribute", CONF_MSTR, &addattrs,
			  "addVendorAttribute", CONF_MSTR, &addvattrs,
			  "modifyAttribute", CONF_MSTR, &modattrs,
			  NULL
	    ))
	debugx(1, DBG_ERR, "configuration error");
    addrewrite(val, rmattrs, rmvattrs, addattrs, addvattrs, modattrs);
    return 1;
}

int setprotoopts(uint8_t type, char **listenargs, char *sourcearg) {
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
    char *sourcearg[RAD_PROTOCOUNT];
#if defined(WANT_FTICKS)
    uint8_t *fticks_reporting_str = NULL;
    uint8_t *fticks_mac_str = NULL;
    uint8_t *fticks_key_str = NULL;
#endif
    int i;

    cfs = openconfigfile(configfile);
    memset(&options, 0, sizeof(options));
    memset(&listenargs, 0, sizeof(listenargs));
    memset(&sourcearg, 0, sizeof(sourcearg));

    clconfs = list_create();
    if (!clconfs)
	debugx(1, DBG_ERR, "malloc failed");

    srvconfs = list_create();
    if (!srvconfs)
	debugx(1, DBG_ERR, "malloc failed");

    realms = list_create();
    if (!realms)
	debugx(1, DBG_ERR, "malloc failed");

    rewriteconfs = hash_create();
    if (!rewriteconfs)
	debugx(1, DBG_ERR, "malloc failed");

    if (!getgenericconfig(
	    &cfs, NULL,
#ifdef RADPROT_UDP
	    "ListenUDP", CONF_MSTR, &listenargs[RAD_UDP],
	    "SourceUDP", CONF_STR, &sourcearg[RAD_UDP],
#endif
#ifdef RADPROT_TCP
	    "ListenTCP", CONF_MSTR, &listenargs[RAD_TCP],
	    "SourceTCP", CONF_STR, &sourcearg[RAD_TCP],
#endif
#ifdef RADPROT_TLS
	    "ListenTLS", CONF_MSTR, &listenargs[RAD_TLS],
	    "SourceTLS", CONF_STR, &sourcearg[RAD_TLS],
#endif
#ifdef RADPROT_DTLS
	    "ListenDTLS", CONF_MSTR, &listenargs[RAD_DTLS],
	    "SourceDTLS", CONF_STR, &sourcearg[RAD_DTLS],
#endif
            "PidFile", CONF_STR, &options.pidfile,
	    "TTLAttribute", CONF_STR, &options.ttlattr,
	    "addTTL", CONF_LINT, &addttl,
	    "LogLevel", CONF_LINT, &loglevel,
	    "LogDestination", CONF_STR, &options.logdestination,
	    "LoopPrevention", CONF_BLN, &options.loopprevention,
	    "Client", CONF_CBK, confclient_cb, NULL,
	    "Server", CONF_CBK, confserver_cb, NULL,
	    "Realm", CONF_CBK, confrealm_cb, NULL,
#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
	    "TLS", CONF_CBK, conftls_cb, NULL,
#endif
	    "Rewrite", CONF_CBK, confrewrite_cb, NULL,
#if defined(WANT_FTICKS)
	    "FTicksReporting", CONF_STR, &fticks_reporting_str,
	    "FTicksMAC", CONF_STR, &fticks_mac_str,
	    "FTicksKey", CONF_STR, &fticks_key_str,
	    "FTicksSyslogFacility", CONF_STR, &options.ftickssyslogfacility,
#endif
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
    if (addttl != LONG_MIN) {
	if (addttl < 1 || addttl > 255)
	    debugx(1, DBG_ERR, "error in %s, value of option addTTL is %d, must be 1-255", configfile, addttl);
	options.addttl = (uint8_t)addttl;
    }
    if (!setttlattr(&options, DEFAULT_TTL_ATTR))
    	debugx(1, DBG_ERR, "Failed to set TTLAttribute, exiting");

#if defined(WANT_FTICKS)
    fticks_configure(&options, &fticks_reporting_str, &fticks_mac_str,
		     &fticks_key_str);
#endif

    for (i = 0; i < RAD_PROTOCOUNT; i++)
	if (listenargs[i] || sourcearg[i])
	    setprotoopts(i, listenargs[i], sourcearg[i]);
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
    sslinit();

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
#if defined(WANT_FTICKS)
    	if (options.ftickssyslogfacility) {
            debug_set_destination(options.ftickssyslogfacility,
                                  LOG_TYPE_FTICKS);
            free(options.ftickssyslogfacility);
    	}
#endif
    }
    free(options.logdestination);

    if (!list_first(clconfs))
	debugx(1, DBG_ERR, "No clients configured, nothing to do, exiting");
    if (!list_first(realms))
	debugx(1, DBG_ERR, "No realms configured, nothing to do, exiting");

    if (pretend)
	debugx(0, DBG_ERR, "All OK so far; exiting since only pretending");

    if (!foreground && (daemon(0, 0) < 0))
	debugx(1, DBG_ERR, "daemon() failed: %s", strerror(errno));

    debug_timestamp_on();
    debug(DBG_INFO, "radsecproxy revision %s starting", PACKAGE_VERSION);
    if (!pidfile)
        pidfile = options.pidfile;
    if (pidfile && !createpidfile(pidfile))
	debugx(1, DBG_ERR, "failed to create pidfile %s: %s", pidfile, strerror(errno));

    sigemptyset(&sigset);
    /* exit on all but SIGHUP|SIGPIPE, ignore more? */
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    pthread_create(&sigth, &pthread_attr, sighandler, NULL);

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
