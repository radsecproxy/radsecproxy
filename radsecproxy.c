/*
 * Copyright (C) 2006 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

/* BUGS:
 * peers can not yet be specified with literal IPv6 addresses due to port syntax
 */

/* TODO:
 * Among other things:
 * timer based client retrans or maybe no retrans and just a timer...
 * make our server ignore client retrans?
 * tls keep alives
 * routing based on id....
 * need to also encrypt Tunnel-Password and Message-Authenticator attrs
 * tls certificate validation
*/

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
 * Example: With 3 UDP peer and 30 TLS peers, there will be a max of
 *          1 + (2 + 2 * 3) + (2 * 30) + (2 * 30) = 129 threads
*/

#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include "radsecproxy.h"

static struct client clients[MAX_PEERS];
static struct server servers[MAX_PEERS];

static int client_count = 0;
static int server_count = 0;

static struct replyq udp_server_replyq;
static int udp_server_sock = -1;
static char *udp_server_port = DEFAULT_UDP_PORT;
static pthread_mutex_t *ssl_locks;
static long *ssl_lock_count;
static SSL_CTX *ssl_ctx_cl;
extern int optind;
extern char *optarg;

/* callbacks for making OpenSSL thread safe */
unsigned long ssl_thread_id() {
        return (unsigned long)pthread_self();
};

void ssl_locking_callback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
	pthread_mutex_lock(&ssl_locks[type]);
	ssl_lock_count[type]++;
    } else
	pthread_mutex_unlock(&ssl_locks[type]);
}

void ssl_locks_setup() {
    int i;

    ssl_locks = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    ssl_lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
	ssl_lock_count[i] = 0;
	pthread_mutex_init(&ssl_locks[i], NULL);
    }

    CRYPTO_set_id_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_locking_callback);
}

int resolvepeer(struct peer *peer) {
    struct addrinfo hints, *addrinfo;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = (peer->type == 'T' ? SOCK_STREAM : SOCK_DGRAM);
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(peer->host, peer->port, &hints, &addrinfo)) {
	err("resolvepeer: can't resolve %s port %s", peer->host, peer->port);
	return 0;
    }

    if (peer->addrinfo)
	freeaddrinfo(peer->addrinfo);
    peer->addrinfo = addrinfo;
    return 1;
}	  

int connecttoserver(struct addrinfo *addrinfo) {
    int s;
    struct addrinfo *res;
    
    for (res = addrinfo; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            err("connecttoserver: socket failed");
            continue;
        }
        if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
            break;
        err("connecttoserver: connect failed");
        close(s);
        s = -1;
    }
    return s;
}	  

/* returns the client with matching address, or NULL */
/* if client argument is not NULL, we only check that one client */
struct client *find_client(char type, struct sockaddr *addr, struct client *client) {
    struct sockaddr_in6 *sa6;
    struct in_addr *a4 = NULL;
    struct client *c;
    int i;
    struct addrinfo *res;

    if (addr->sa_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
            a4 = (struct in_addr *)&sa6->sin6_addr.s6_addr[12];
    } else
	a4 = &((struct sockaddr_in *)addr)->sin_addr;

    c = (client ? client : clients);
    for (i = 0; i < client_count; i++) {
	if (c->peer.type == type)
	    for (res = c->peer.addrinfo; res; res = res->ai_next)
		if ((a4 && res->ai_family == AF_INET &&
		     !memcmp(a4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4)) ||
		    (res->ai_family == AF_INET6 &&
		     !memcmp(&sa6->sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, 16)))
		    return c;
	if (client)
	    break;
	c++;
    }
    return NULL;
}

/* returns the server with matching address, or NULL */
/* if server argument is not NULL, we only check that one server */
struct server *find_server(char type, struct sockaddr *addr, struct server *server) {
    struct sockaddr_in6 *sa6;
    struct in_addr *a4 = NULL;
    struct server *s;
    int i;
    struct addrinfo *res;

    if (addr->sa_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
            a4 = (struct in_addr *)&sa6->sin6_addr.s6_addr[12];
    } else
	a4 = &((struct sockaddr_in *)addr)->sin_addr;

    s = (server ? server : servers);
    for (i = 0; i < server_count; i++) {
	if (s->peer.type == type)
	    for (res = s->peer.addrinfo; res; res = res->ai_next)
		if ((a4 && res->ai_family == AF_INET &&
		     !memcmp(a4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4)) ||
		    (res->ai_family == AF_INET6 &&
		     !memcmp(&sa6->sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, 16)))
		    return s;
	if (server)
	    break;
	s++;
    }
    return NULL;
}

/* exactly one of client and server must be non-NULL */
/* if *peer == NULL we return who we received from, else require it to be from peer */
/* return from in sa if not NULL */
unsigned char *radudpget(int s, struct client **client, struct server **server, struct sockaddr_storage *sa) {
    int cnt, len;
    void *f;
    unsigned char buf[65536], *rad;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);

    for (;;) {
	cnt = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
	if (cnt == -1) {
	    err("radudpget: recv failed");
	    continue;
	}
	printf("radudpget: got %d bytes from %s\n", cnt, addr2string((struct sockaddr *)&from, fromlen));

	if (cnt < 20) {
	    printf("radudpget: packet too small\n");
	    continue;
	}
    
	len = RADLEN(buf);

	if (cnt < len) {
	    printf("radudpget: packet smaller than length field in radius header\n");
	    continue;
	}
	if (cnt > len)
	    printf("radudpget: packet was padded with %d bytes\n", cnt - len);

	f = (client
	     ? (void *)find_client('U', (struct sockaddr *)&from, *client)
	     : (void *)find_server('U', (struct sockaddr *)&from, *server));
	if (!f) {
	    printf("radudpget: got packet from wrong or unknown UDP peer, ignoring\n");
	    continue;
	}

	rad = malloc(len);
	if (rad)
	    break;
	err("radudpget: malloc failed");
    }
    memcpy(rad, buf, len);
    if (client)
	*client = (struct client *)f; /* only need this if *client == NULL, but if not NULL *client == f here */
    else
	*server = (struct server *)f; /* only need this if *server == NULL, but if not NULL *server == f here */
    if (sa)
	*sa = from;
    return rad;
}

void tlsconnect(struct server *server, struct timeval *when, char *text) {
    struct timeval now;
    time_t elapsed;
    unsigned long error;

    printf("tlsconnect called from %s\n", text);
    pthread_mutex_lock(&server->lock);
    if (when && memcmp(&server->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	printf("tlsconnect(%s): seems already reconnected\n", text);
	pthread_mutex_unlock(&server->lock);
	return;
    }

    printf("tlsconnect %s\n", text);

    for (;;) {
	gettimeofday(&now, NULL);
	elapsed = now.tv_sec - server->lastconnecttry.tv_sec;
	if (server->connectionok) {
	    server->connectionok = 0;
	    sleep(10);
	} else if (elapsed < 5)
	    sleep(10);
	else if (elapsed < 600)
	    sleep(elapsed * 2);
	else if (elapsed < 10000) /* no sleep at startup */
		sleep(900);
	printf("tlsconnect: trying to open TLS connection to %s port %s\n", server->peer.host, server->peer.port);
	if (server->sock >= 0)
	    close(server->sock);
	if ((server->sock = connecttoserver(server->peer.addrinfo)) < 0)
	    continue;
	SSL_free(server->peer.ssl);
	server->peer.ssl = SSL_new(ssl_ctx_cl);
	SSL_set_fd(server->peer.ssl, server->sock);
	if (SSL_connect(server->peer.ssl) > 0)
	    break;
	while ((error = ERR_get_error()))
	    err("tlsconnect: TLS: %s", ERR_error_string(error, NULL));
    }
    printf("tlsconnect: TLS connection to %s port %s up\n", server->peer.host, server->peer.port);
    gettimeofday(&server->lastconnecttry, NULL);
    pthread_mutex_unlock(&server->lock);
}

unsigned char *radtlsget(SSL *ssl) {
    int cnt, total, len;
    unsigned char buf[4], *rad;

    for (;;) {
	for (total = 0; total < 4; total += cnt) {
	    cnt = SSL_read(ssl, buf + total, 4 - total);
	    if (cnt <= 0) {
		printf("radtlsget: connection lost\n");
		return NULL;
	    }
	}

	len = RADLEN(buf);
	rad = malloc(len);
	if (!rad) {
	    err("radtlsget: malloc failed");
	    continue;
	}
	memcpy(rad, buf, 4);

	for (; total < len; total += cnt) {
	    cnt = SSL_read(ssl, rad + total, len - total);
	    if (cnt <= 0) {
		printf("radtlsget: connection lost\n");
		free(rad);
		return NULL;
	    }
	}
    
	if (total >= 20)
	    break;
	
	free(rad);
	printf("radtlsget: packet smaller than minimum radius size\n");
    }
    
    printf("radtlsget: got %d bytes\n", total);
    return rad;
}

int clientradput(struct server *server, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct timeval lastconnecttry;
    
    len = RADLEN(rad);
    if (server->peer.type == 'U') {
	if (send(server->sock, rad, len, 0) >= 0) {
	    printf("clienradput: sent UDP of length %d to %s port %s\n", len, server->peer.host, server->peer.port);
	    return 1;
	}
	err("clientradput: send failed");
	return 0;
    }

    lastconnecttry = server->lastconnecttry;
    while ((cnt = SSL_write(server->peer.ssl, rad, len)) <= 0) {
	while ((error = ERR_get_error()))
	    err("clientwr: TLS: %s", ERR_error_string(error, NULL));
	tlsconnect(server, &lastconnecttry, "clientradput");
	lastconnecttry = server->lastconnecttry;
    }

    server->connectionok = 1;
    printf("clientradput: Sent %d bytes, Radius packet of length %d to TLS peer %s\n",
	   cnt, len, server->peer.host);
    return 1;
}

int radsign(unsigned char *rad, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned int md_len;
    int result;
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    result = (EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) &&
	EVP_DigestUpdate(&mdctx, rad, RADLEN(rad)) &&
	EVP_DigestUpdate(&mdctx, sec, strlen(sec)) &&
	EVP_DigestFinal_ex(&mdctx, rad + 4, &md_len) &&
	md_len == 16);
    pthread_mutex_unlock(&lock);
    return result;
}

int validauth(unsigned char *rad, unsigned char *reqauth, unsigned char *sec) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    int result;
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    len = RADLEN(rad);
    
    result = (EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) &&
	      EVP_DigestUpdate(&mdctx, rad, 4) &&
	      EVP_DigestUpdate(&mdctx, reqauth, 16) &&
	      (len <= 20 || EVP_DigestUpdate(&mdctx, rad + 20, len - 20)) &&
	      EVP_DigestUpdate(&mdctx, sec, strlen(sec)) &&
	      EVP_DigestFinal_ex(&mdctx, hash, &len) &&
	      len == 16 &&
	      !memcmp(hash, rad + 4, 16));
    pthread_mutex_unlock(&lock);
    return result;
}
	      
void sendrq(struct server *to, struct client *from, struct request *rq) {
    int i;

    pthread_mutex_lock(&to->newrq_mutex);
    for (i = 0; i < MAX_REQUESTS; i++)
	if (!to->requests[i].buf)
	    break;
    if (i == MAX_REQUESTS) {
	printf("No room in queue, dropping request\n");
	pthread_mutex_unlock(&to->newrq_mutex);
	return;
    }
    
    rq->buf[1] = (char)i;
    to->requests[i] = *rq;

    if (!to->newrq) {
	to->newrq = 1;
	printf("signalling client writer\n");
	pthread_cond_signal(&to->newrq_cond);
    }
    pthread_mutex_unlock(&to->newrq_mutex);
}

void sendreply(struct client *to, struct server *from, char *buf, struct sockaddr_storage *tosa) {
    struct replyq *replyq = to->replyq;
    
    pthread_mutex_lock(&replyq->count_mutex);
    if (replyq->count == replyq->size) {
	printf("No room in queue, dropping request\n");
	pthread_mutex_unlock(&replyq->count_mutex);
	return;
    }

    replyq->replies[replyq->count].buf = buf;
    if (tosa)
	replyq->replies[replyq->count].tosa = *tosa;
    replyq->count++;

    if (replyq->count == 1) {
	printf("signalling client writer\n");
	pthread_cond_signal(&replyq->count_cond);
    }
    pthread_mutex_unlock(&replyq->count_mutex);
}

int pwdcrypt(uint8_t *plain, uint8_t *enc, uint8_t enclen, uint8_t *shared, uint8_t sharedlen,
		uint8_t *auth) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE], *input;
    unsigned int md_len;
    uint8_t i, offset = 0;
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    input = auth;
    for (;;) {
	if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	    !EVP_DigestUpdate(&mdctx, shared, sharedlen) ||
	    !EVP_DigestUpdate(&mdctx, input, 16) ||
	    !EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	    md_len != 16) {
	    pthread_mutex_unlock(&lock);
	    return 0;
	}
	for (i = 0; i < 16; i++)
	    plain[offset + i] = hash[i] ^ enc[offset + i];
	offset += 16;
	if (offset == enclen)
	    break;
	input = enc + offset - 16;
    }
    pthread_mutex_unlock(&lock);
    return 1;
}

struct server *id2server(char *id, uint8_t len) {
    int i;
    char **realm, *idrealm;

    idrealm = strchr(id, '@');
    if (idrealm) {
	idrealm++;
	len -= idrealm - id;
    } else {
	idrealm = "-";
	len = 1;
    }
    for (i = 0; i < server_count; i++) {
	for (realm = servers[i].realms; *realm; realm++) {
	    if ((strlen(*realm) == 1 && **realm == '*') ||
		(strlen(*realm) == len && !memcmp(idrealm, *realm, len))) {
		printf("found matching realm: %s, host %s\n", *realm, servers[i].peer.host);
		return servers + i;
	    }
	}
    }
    return NULL;
}

int messageauth(char *rad, uint8_t *authattr, uint8_t *newauth, struct peer *from, struct peer *to) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static EVP_MD_CTX mdctx;
    unsigned int md_len;
    uint8_t auth[16], hash[EVP_MAX_MD_SIZE];
    
    pthread_mutex_lock(&lock);
    if (first) {
	EVP_MD_CTX_init(&mdctx);
	first = 0;
    }

    memcpy(auth, authattr, 16);
    memset(authattr, 0, 16);
    
    if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	!EVP_DigestUpdate(&mdctx, from->secret, strlen(from->secret)) ||
	!EVP_DigestUpdate(&mdctx, rad, RADLEN(rad)) ||
	!EVP_DigestFinal_ex(&mdctx, hash, &md_len) ||
	md_len != 16) {
	printf("message auth computation failed\n");
	pthread_mutex_unlock(&lock);
	return 0;
    }

    if (memcmp(auth, hash, 16)) {
	printf("message authenticator, wrong value\n");
	pthread_mutex_unlock(&lock);
	return 0;
    }	
	
    if (!EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL) ||
	!EVP_DigestUpdate(&mdctx, to->secret, strlen(to->secret)) ||
	!EVP_DigestUpdate(&mdctx, rad, RADLEN(rad)) ||
	!EVP_DigestFinal_ex(&mdctx, authattr, &md_len) ||
	md_len != 16) {
	printf("message auth recomputation failed\n");
	pthread_mutex_unlock(&lock);
	return 0;
    }
	
    pthread_mutex_unlock(&lock);
    return 1;
}

struct server *radsrv(struct request *rq, char *buf, struct client *from) {
    uint8_t code, id, *auth, *attr, pwd[128], attrvallen;
    uint8_t *usernameattr = NULL, *userpwdattr = NULL, *tunnelpwdattr = NULL, *messageauthattr = NULL;
    int i;
    uint16_t len;
    int left;
    struct server *to;
    unsigned char newauth[16];
    
    code = *(uint8_t *)buf;
    id = *(uint8_t *)(buf + 1);
    len = RADLEN(buf);
    auth = (uint8_t *)(buf + 4);

    printf("radsrv: code %d, id %d, length %d\n", code, id, len);
    
    if (code != RAD_Access_Request) {
	printf("radsrv: server currently accepts only access-requests, ignoring\n");
	return NULL;
    }

    left = len - 20;
    attr = buf + 20;
    
    while (left > 1) {
	left -= attr[RAD_Attr_Length];
	if (left < 0) {
	    printf("radsrv: attribute length exceeds packet length, ignoring packet\n");
	    return NULL;
	}
	switch (attr[RAD_Attr_Type]) {
	case RAD_Attr_User_Name:
	    usernameattr = attr;
	    break;
	case RAD_Attr_User_Password:
	    userpwdattr = attr;
	    break;
	case RAD_Attr_Tunnel_Password:
	    tunnelpwdattr = attr;
	    break;
	case RAD_Attr_Message_Authenticator:
	    messageauthattr = attr;
	    break;
	}
	attr += attr[RAD_Attr_Length];
    }
    if (left)
	printf("radsrv: malformed packet? remaining byte after last attribute\n");

    if (usernameattr) {
	printf("radsrv: Username: ");
	for (i = 0; i < usernameattr[RAD_Attr_Length] - 2; i++)
	    printf("%c", usernameattr[RAD_Attr_Value + i]);
	printf("\n");
    }

    to = id2server(&usernameattr[RAD_Attr_Value], usernameattr[RAD_Attr_Length] - 2);
    if (!to) {
	printf("radsrv: ignoring request, don't know where to send it\n");
	return NULL;
    }

    if (!RAND_bytes(newauth, 16)) {
	printf("radsrv: failed to generate random auth\n");
	return NULL;
    }

    if (messageauthattr && (messageauthattr[RAD_Attr_Length] != 18 ||
			    !messageauth(buf, &messageauthattr[RAD_Attr_Value], newauth, &from->peer, &to->peer))) {
	printf("radsrv: message authentication failed\n");
	return NULL;
    }

    if (userpwdattr) {
	printf("radsrv: found userpwdattr of length %d\n", userpwdattr[RAD_Attr_Length]);
	attrvallen = userpwdattr[RAD_Attr_Length] - 2;
	if (attrvallen < 16 || attrvallen > 128 || attrvallen % 16) {
	    printf("radsrv: invalid user password length\n");
	    return NULL;
	}
	
	if (!pwdcrypt(pwd, &userpwdattr[RAD_Attr_Value], attrvallen, from->peer.secret, strlen(from->peer.secret), auth)) {
	    printf("radsrv: cannot decrypt password\n");
	    return NULL;
	}
	printf("radsrv: password: ");
	for (i = 0; i < attrvallen; i++)
	    printf("%02x ", pwd[i]);
	printf("\n");
	if (!pwdcrypt(&userpwdattr[RAD_Attr_Value], pwd, attrvallen, to->peer.secret, strlen(to->peer.secret), newauth)) {
	    printf("radsrv: cannot encrypt password\n");
	    return NULL;
	}
    }

    if (tunnelpwdattr) {
	printf("radsrv: found tunnelpwdattr of length %d\n", tunnelpwdattr[RAD_Attr_Length]);
	attrvallen = tunnelpwdattr[RAD_Attr_Length] - 2;
	if (attrvallen < 16 || attrvallen > 128 || attrvallen % 16) {
	    printf("radsrv: invalid user password length\n");
	    return NULL;
	}
	
	if (!pwdcrypt(pwd, &tunnelpwdattr[RAD_Attr_Value], attrvallen, from->peer.secret, strlen(from->peer.secret), auth)) {
	    printf("radsrv: cannot decrypt password\n");
	    return NULL;
	}
	printf("radsrv: password: ");
	for (i = 0; i < attrvallen; i++)
	    printf("%02x ", pwd[i]);
	printf("\n");
	if (!pwdcrypt(&tunnelpwdattr[RAD_Attr_Value], pwd, attrvallen, to->peer.secret, strlen(to->peer.secret), newauth)) {
	    printf("radsrv: cannot encrypt password\n");
	    return NULL;
	}
    }

    rq->buf = buf;
    rq->from = from;
    rq->origid = id;
    memcpy(rq->origauth, auth, 16);
    memcpy(rq->buf + 4, newauth, 16);
    return to;
}

void *clientrd(void *arg) {
    struct server *server = (struct server *)arg;
    struct client *from;
    int i;
    unsigned char *buf;
    struct sockaddr_storage fromsa;
    struct timeval lastconnecttry;
    
    for (;;) {
	lastconnecttry = server->lastconnecttry;
	buf = (server->peer.type == 'U' ? radudpget(server->sock, NULL, &server, NULL) : radtlsget(server->peer.ssl));
	if (!buf && server->peer.type == 'T') {
	    tlsconnect(server, &lastconnecttry, "clientrd");
	    continue;
	}
    
	server->connectionok = 1;
	
	i = buf[1]; /* i is the id */

	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->requests[i].buf || !server->requests[i].tries) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    printf("clientrd: no matching request sent with this id, ignoring\n");
	    continue;
	}
        
	if (server->requests[i].received) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    printf("clientrd: already received, ignoring\n");
	    continue;
	}

	if (!validauth(buf, server->requests[i].buf + 4, server->peer.secret)) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    printf("clientrd: invalid auth, ignoring\n");
	    continue;
	}

	/* once we set received = 1, requests[i] may be reused */
	buf[1] = (char)server->requests[i].origid;
	memcpy(buf + 4, server->requests[i].origauth, 16);
	from = server->requests[i].from;
	if (from->peer.type == 'U')
	    fromsa = server->requests[i].fromsa;
	server->requests[i].received = 1;
	pthread_mutex_unlock(&server->newrq_mutex);

	if (!radsign(buf, from->peer.secret)) {
	    printf("clientrd: failed to sign message\n");
	    continue;
	}
	
	printf("clientrd: giving packet back to where it came from\n");
	sendreply(from, server, buf, from->peer.type == 'U' ? &fromsa : NULL);
    }
}

void *clientwr(void *arg) {
    struct server *server = (struct server *)arg;
    pthread_t clientrdth;
    int i;

    if (server->peer.type == 'U') {
	if ((server->sock = connecttoserver(server->peer.addrinfo)) < 0) {
	    printf("clientwr: connecttoserver failed\n");
	    exit(1);
	}
    } else
	tlsconnect(server, NULL, "new client");
    
    if (pthread_create(&clientrdth, NULL, clientrd, (void *)server))
	errx("clientwr: pthread_create failed");

    for (;;) {
	pthread_mutex_lock(&server->newrq_mutex);
	while (!server->newrq) {
	    printf("clientwr: waiting for signal\n");
	    pthread_cond_wait(&server->newrq_cond, &server->newrq_mutex);
	    printf("clientwr: got signal\n");
	}
	server->newrq = 0;
	pthread_mutex_unlock(&server->newrq_mutex);
	       
	for (i = 0; i < MAX_REQUESTS; i++) {
	    pthread_mutex_lock(&server->newrq_mutex);
	    while (!server->requests[i].buf && i < MAX_REQUESTS)
		i++;
	    if (i == MAX_REQUESTS) {
		pthread_mutex_unlock(&server->newrq_mutex);
		break;
	    }

	    /* already received or too many tries */
            if (server->requests[i].received || server->requests[i].tries > 2) {
                free(server->requests[i].buf);
                /* setting this to NULL means that it can be reused */
                server->requests[i].buf = NULL;
                pthread_mutex_unlock(&server->newrq_mutex);
                continue;
            }
            pthread_mutex_unlock(&server->newrq_mutex);
            
            server->requests[i].tries++;
	    clientradput(server, server->requests[i].buf);
	}
    }
    /* should do more work to maintain TLS connections, keepalives etc */
}

void *udpserverwr(void *arg) {
    struct replyq *replyq = &udp_server_replyq;
    struct reply *reply = replyq->replies;
    
    pthread_mutex_lock(&replyq->count_mutex);
    for (;;) {
	while (!replyq->count) {
	    printf("udp server writer, waiting for signal\n");
	    pthread_cond_wait(&replyq->count_cond, &replyq->count_mutex);
	    printf("udp server writer, got signal\n");
	}
	pthread_mutex_unlock(&replyq->count_mutex);
	
	if (sendto(udp_server_sock, reply->buf, RADLEN(reply->buf), 0,
		   (struct sockaddr *)&reply->tosa, SOCKADDR_SIZE(reply->tosa)) < 0)
	    err("sendudp: send failed");
	free(reply->buf);
	
	pthread_mutex_lock(&replyq->count_mutex);
	replyq->count--;
	memmove(replyq->replies, replyq->replies + 1,
		replyq->count * sizeof(struct reply));
    }
}

void *udpserverrd(void *arg) {
    struct request rq;
    unsigned char *buf;
    struct server *to;
    struct client *fr;
    pthread_t udpserverwrth;
    
    if ((udp_server_sock = bindport(SOCK_DGRAM, udp_server_port)) < 0) {
        printf("udpserverrd: socket/bind failed\n");
	exit(1);
    }
    printf("udpserverrd: listening on UDP port %s\n", udp_server_port);

    if (pthread_create(&udpserverwrth, NULL, udpserverwr, NULL))
	errx("pthread_create failed");
    
    for (;;) {
	fr = NULL;
	memset(&rq, 0, sizeof(struct request));
	buf = radudpget(udp_server_sock, &fr, NULL, &rq.fromsa);
	to = radsrv(&rq, buf, fr);
	if (!to) {
	    printf("udpserverrd: ignoring request, no place to send it\n");
	    continue;
	}
	sendrq(to, fr, &rq);
    }
}

void *tlsserverwr(void *arg) {
    int cnt;
    unsigned long error;
    struct client *client = (struct client *)arg;
    struct replyq *replyq;
    
    pthread_mutex_lock(&client->replycount_mutex);
    for (;;) {
	replyq = client->replyq;
	while (!replyq->count) {
	    printf("tls server writer, waiting for signal\n");
	    pthread_cond_wait(&replyq->count_cond, &replyq->count_mutex);
	    printf("tls server writer, got signal\n");
	}
	pthread_mutex_unlock(&replyq->count_mutex);
	cnt = SSL_write(client->peer.ssl, replyq->replies->buf, RADLEN(replyq->replies->buf));
	if (cnt > 0)
	    printf("tlsserverwr: Sent %d bytes, Radius packet of length %d\n",
		   cnt, RADLEN(replyq->replies->buf));
	else
	    while ((error = ERR_get_error()))
		err("tlsserverwr: SSL: %s", ERR_error_string(error, NULL));
	free(replyq->replies->buf);

	pthread_mutex_lock(&replyq->count_mutex);
	replyq->count--;
	memmove(replyq->replies, replyq->replies + 1, replyq->count * sizeof(struct reply));
    }
}

void *tlsserverrd(void *arg) {
    struct request rq;
    char unsigned *buf;
    unsigned long error;
    struct server *to;
    int s;
    struct client *client = (struct client *)arg;
    pthread_t tlsserverwrth;

    printf("tlsserverrd starting\n");
    if (SSL_accept(client->peer.ssl) <= 0) {
        while ((error = ERR_get_error()))
            err("tlsserverrd: SSL: %s", ERR_error_string(error, NULL));
        errx("accept failed, child exiting");
    }

    if (pthread_create(&tlsserverwrth, NULL, tlsserverwr, (void *)client))
	errx("pthread_create failed");
    
    for (;;) {
	buf = radtlsget(client->peer.ssl);
	if (!buf) {
	    printf("tlsserverrd: connection lost\n");
	    s = SSL_get_fd(client->peer.ssl);
	    SSL_free(client->peer.ssl);
	    client->peer.ssl = NULL;
	    if (s >= 0)
		close(s);
	    pthread_exit(NULL);
	}
	printf("tlsserverrd: got Radius message from %s\n", client->peer.host);
	memset(&rq, 0, sizeof(struct request));
	to = radsrv(&rq, buf, client);
	if (!to) {
	    printf("ignoring request, no place to send it\n");
	    continue;
	}
	sendrq(to, client, &rq);
    }
}

int tlslistener(SSL_CTX *ssl_ctx) {
    pthread_t tlsserverth;
    int s, snew;
    struct sockaddr_storage from;
    size_t fromlen = sizeof(from);
    struct client *client;

    if ((s = bindport(SOCK_STREAM, DEFAULT_TLS_PORT)) < 0) {
        printf("tlslistener: socket/bind failed\n");
	exit(1);
    }
    
    listen(s, 0);
    printf("listening for incoming TLS on port %s\n", DEFAULT_TLS_PORT);

    for (;;) {
	snew = accept(s, (struct sockaddr *)&from, &fromlen);
	if (snew < 0)
	    errx("accept failed");
	printf("incoming TLS connection from %s\n", addr2string((struct sockaddr *)&from, fromlen));

	client = find_client('T', (struct sockaddr *)&from, NULL);
	if (!client) {
	    printf("ignoring request, not a known TLS client\n");
	    close(snew);
	    continue;
	}

	if (client->peer.ssl) {
	    printf("Ignoring incoming connection, already have one from this client\n");
	    close(snew);
	    continue;
	}
	client->peer.ssl = SSL_new(ssl_ctx);
	SSL_set_fd(client->peer.ssl, snew);
	if (pthread_create(&tlsserverth, NULL, tlsserverrd, (void *)client))
	    errx("pthread_create failed");
    }
    return 0;
}

char *parsehostport(char *s, struct peer *peer) {
    char *p, *field;
    int ipv6 = 0;

    p = s;
    // allow literal addresses and port, e.g. [2001:db8::1]:1812
    if (*p == '[') {
	p++;
	field = p;
	for (; *p && *p != ']' && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	if (*p != ']') {
	    printf("no ] matching initial [\n");
	    exit(1);
	}
	ipv6 = 1;
    } else {
	field = p;
	for (; *p && *p != ':' && *p != ' ' && *p != '\t' && *p != '\n'; p++);
    }
    if (field == p) {
	printf("missing host/address\n");
	exit(1);
    }
    peer->host = malloc(p - field + 1);
    if (!peer->host)
	errx("malloc failed");
    memcpy(peer->host, field, p - field);
    peer->host[p - field] = '\0';
    if (ipv6) {
	p++;
	if (*p && *p != ':' && *p != ' ' && *p != '\t' && *p != '\n') {
	    printf("unexpected character after ]\n");
	    exit(1);
	}
    }
    if (*p == ':') {
	    /* port number or service name is specified */;
	    field = p++;
	    for (; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	    if (field == p) {
		printf("syntax error, : but no following port\n");
		exit(1);
	    }
	    peer->port = malloc(p - field + 1);
	    if (!peer->port)
		errx("malloc failed");
	    memcpy(peer->port, field, p - field);
	    peer->port[p - field] = '\0';
    } else
        peer->port = NULL;
    return p;
}

// * is default, else longest match ... ";" used for separator
char *parserealmlist(char *s, struct server *server) {
    char *p;
    int i, n, l;

    for (p = s, n = 1; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++)
	if (*p == ';')
	    n++;
    l = p - s;
    if (!l) {
	server->realms = NULL;
	return p;
    }
    server->realmdata = malloc(l + 1);
    if (!server->realmdata)
	errx("malloc failed");
    memcpy(server->realmdata, s, l);
    server->realmdata[l] = '\0';
    server->realms = malloc((1+n) * sizeof(char *));
    if (!server->realms)
	errx("malloc failed");
    server->realms[0] = server->realmdata;
    for (n = 1, i = 0; i < l; i++)
	if (server->realmdata[i] == ';') {
	    server->realmdata[i] = '\0';
	    server->realms[n++] = server->realmdata + i + 1;
	}	
    server->realms[n] = NULL;
    return p;
}

/* exactly one argument must be non-NULL */
void getconfig(const char *serverfile, const char *clientfile) {
    FILE *f;
    char line[1024];
    char *p, *field, **r;
    struct client *client;
    struct server *server;
    struct peer *peer;
    int *count;
    
    if (serverfile) {
	printf("opening file %s for reading\n", serverfile);
	f = fopen(serverfile, "r");
	if (!f)
	    errx("getconfig failed to open %s for reading", serverfile);
	count = &server_count;
    } else {
	printf("opening file %s for reading\n", clientfile);
	f = fopen(clientfile, "r");
	if (!f)
	    errx("getconfig failed to open %s for reading", clientfile);
	udp_server_replyq.replies = malloc(4 * MAX_REQUESTS * sizeof(struct reply));
	if (!udp_server_replyq.replies)
	    errx("malloc failed");
	udp_server_replyq.size = 4 * MAX_REQUESTS;
	udp_server_replyq.count = 0;
	pthread_mutex_init(&udp_server_replyq.count_mutex, NULL);
	pthread_cond_init(&udp_server_replyq.count_cond, NULL);
	count = &client_count;
    }    
    
    *count = 0;
    while (fgets(line, 1024, f) && *count < MAX_PEERS) {
	if (serverfile) {
	    server = &servers[*count];
	    memset(server, 0, sizeof(struct server));
	    peer = &server->peer;
	} else {
	    client = &clients[*count];
	    memset(client, 0, sizeof(struct client));
	    peer = &client->peer;
	}
	for (p = line; *p == ' ' || *p == '\t'; p++);
	if (*p == '#' || *p == '\n')
	    continue;
	if (*p != 'U' && *p != 'T') {
	    printf("server type must be U or T, got %c\n", *p);
	    exit(1);
	}
	peer->type = *p;
	for (p++; *p == ' ' || *p == '\t'; p++);
	p = parsehostport(p, peer);
	if (!peer->port)
	    peer->port = (peer->type == 'U' ? DEFAULT_UDP_PORT : DEFAULT_TLS_PORT);
	for (; *p == ' ' || *p == '\t'; p++);
	if (serverfile) {
	    p = parserealmlist(p, server);
	    if (!server->realms) {
		printf("realm list must be specified\n");
		exit(1);
	    }
	    for (; *p == ' ' || *p == '\t'; p++);
	}
	field = p;
	for (; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	if (field == p) {
	    /* no secret set and end of line, line is complete if TLS */
	    if (peer->type == 'U') {
		printf("secret must be specified for UDP\n");
		exit(1);
	    }
	    peer->secret = DEFAULT_TLS_SECRET;
	} else {
	    peer->secret = malloc(p - field + 1);
	    if (!peer->secret)
		errx("malloc failed");
	    memcpy(peer->secret, field, p - field);
	    peer->secret[p - field] = '\0';
	    /* check that rest of line only white space */
	    for (; *p == ' ' || *p == '\t'; p++);
	    if (*p && *p != '\n') {
		printf("max 4 fields per line, found a 5th\n");
		exit(1);
	    }
	}

	if ((serverfile && !resolvepeer(&server->peer)) ||
	    (clientfile && !resolvepeer(&client->peer))) {
	    printf("failed to resolve host %s port %s, exiting\n", peer->host, peer->port);
	    exit(1);
	}

	if (serverfile) {
	    pthread_mutex_init(&server->lock, NULL);
	    server->sock = -1;
	    server->requests = malloc(MAX_REQUESTS * sizeof(struct request));
	    if (!server->requests)
		errx("malloc failed");
	    memset(server->requests, 0, MAX_REQUESTS * sizeof(struct request));
	    server->newrq = 0;
	    pthread_mutex_init(&server->newrq_mutex, NULL);
	    pthread_cond_init(&server->newrq_cond, NULL);
	} else {
	    if (peer->type == 'U')
		client->replyq = &udp_server_replyq;
	    else {
		client->replyq = malloc(sizeof(struct replyq));
		if (!client->replyq)
		    errx("malloc failed");
		client->replyq->replies = malloc(MAX_REQUESTS * sizeof(struct reply));
		if (!client->replyq->replies)
		    errx("malloc failed");
		client->replyq->size = MAX_REQUESTS;
		client->replyq->count = 0;
		pthread_mutex_init(&client->replyq->count_mutex, NULL);
		pthread_cond_init(&client->replyq->count_cond, NULL);
	    }
	}
	printf("got type %c, host %s, port %s, secret %s\n", peer->type, peer->host, peer->port, peer->secret);
	if (serverfile) {
	    printf("    with realms:");
	    for (r = server->realms; *r; r++)
		printf(" %s", *r);
	    printf("\n");
	}
	(*count)++;
    }
    fclose(f);
}

void parseargs(int argc, char **argv) {
    int c;

    while ((c = getopt(argc, argv, "p:")) != -1) {
	switch (c) {
	case 'p':
	    udp_server_port = optarg;
	    break;
	default:
	    goto usage;
	}
    }

    return;

 usage:
    printf("radsecproxy [ -p UDP-port ]\n");
    exit(1);
}
	       
int main(int argc, char **argv) {
    SSL_CTX *ssl_ctx_srv;
    unsigned long error;
    pthread_t udpserverth;
    pthread_attr_t joinable;
    int i;
    
    parseargs(argc, argv);
    getconfig("servers.conf", NULL);
    getconfig(NULL, "clients.conf");
    
    ssl_locks_setup();

    pthread_attr_init(&joinable);
    pthread_attr_setdetachstate(&joinable, PTHREAD_CREATE_JOINABLE);
   
    /* listen on UDP if at least one UDP client */
    
    for (i = 0; i < client_count; i++)
	if (clients[i].peer.type == 'U') {
	    if (pthread_create(&udpserverth, &joinable, udpserverrd, NULL))
		errx("pthread_create failed");
	    break;
	}
    
    /* SSL setup */
    SSL_load_error_strings();
    SSL_library_init();

    while (!RAND_status()) {
	time_t t = time(NULL);
	pid_t pid = getpid();
	RAND_seed((unsigned char *)&t, sizeof(time_t));
        RAND_seed((unsigned char *)&pid, sizeof(pid));
    }
    
    /* initialise client part and start clients */
    ssl_ctx_cl = SSL_CTX_new(TLSv1_client_method());
    if (!ssl_ctx_cl)
	errx("no ssl ctx");
    
    for (i = 0; i < server_count; i++) {
	if (pthread_create(&servers[i].clientth, NULL, clientwr, (void *)&servers[i]))
	    errx("pthread_create failed");
    }

    for (i = 0; i < client_count; i++)
	if (clients[i].peer.type == 'T')
	    break;

    if (i == client_count) {
	printf("No TLS clients defined, not starting TLS listener\n");
	/* just hang around doing nothing, anything to do here? */
	for (;;)
	    sleep(1000);
    }
    
    /* setting up server/daemon part */
    ssl_ctx_srv = SSL_CTX_new(TLSv1_server_method());
    if (!ssl_ctx_srv)
	errx("no ssl ctx");
    if (!SSL_CTX_use_certificate_file(ssl_ctx_srv, "/tmp/server.pem", SSL_FILETYPE_PEM)) {
        while ((error = ERR_get_error()))
            err("SSL: %s", ERR_error_string(error, NULL));
        errx("Failed to load certificate");
    }
    if (!SSL_CTX_use_PrivateKey_file(ssl_ctx_srv, "/tmp/server.key", SSL_FILETYPE_PEM)) {
	while ((error = ERR_get_error()))
	    err("SSL: %s", ERR_error_string(error, NULL));
	errx("Failed to load private key");
    }

    return tlslistener(ssl_ctx_srv);
}
