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

static struct peer peers[MAX_PEERS];
static int peer_count = 0;

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
    struct addrinfo hints;
    
    pthread_mutex_lock(&peer->lock);
    if (peer->addrinfo) {
	/* assume we should re-resolve */
	freeaddrinfo(peer->addrinfo);
	peer->addrinfo = NULL;
    }
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = (peer->type == 'T' ? SOCK_STREAM : SOCK_DGRAM);
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(peer->host, peer->port, &hints, &peer->addrinfo)) {
	err("resolvepeer: can't resolve %s port %s", peer->host, peer->port);
	peer->addrinfo = NULL; /* probably don't need this */
	pthread_mutex_unlock(&peer->lock);
	return 0;
    }
    pthread_mutex_unlock(&peer->lock);
    return 1;
}	  

int connecttopeer(struct peer *peer) {
    int s;
    struct addrinfo *res;
    
    if (!peer->addrinfo) {
	resolvepeer(peer);
	if (!peer->addrinfo) {
	    printf("connecttopeer: can't resolve %s into address to connect to\n", peer->host);
	    return -1;
	}
    }

    for (res = peer->addrinfo; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            err("connecttopeer: socket failed");
            continue;
        }
        if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
            break;
        err("connecttopeer: connect failed");
        close(s);
        s = -1;
    }
    return s;
}	  

/* returns the peer with matching address, or NULL */
/* if peer argument is not NULL, we only check that one peer */
struct peer *find_peer(char type, struct sockaddr *addr, struct peer *peer) {
    struct sockaddr_in6 *sa6;
    struct in_addr *a4 = NULL;
    struct peer *p;
    int i;
    struct addrinfo *res;

    if (addr->sa_family == AF_INET6) {
        sa6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
            a4 = (struct in_addr *)&sa6->sin6_addr.s6_addr[12];
    } else
	a4 = &((struct sockaddr_in *)addr)->sin_addr;

    p = (peer ? peer : peers);
    for (i = 0; i < peer_count; i++) {
	if (p->type == type)
	    for (res = p->addrinfo; res; res = res->ai_next)
		if ((a4 && res->ai_family == AF_INET &&
		     !memcmp(a4, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4)) ||
		    (res->ai_family == AF_INET6 &&
		     !memcmp(&sa6->sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, 16)))
		    return p;
	if (peer)
	    break;
	p++;
    }
    return NULL;
}

/* if *peer == NULL we return who we received from, else require it to be from peer */
/* return from in sa if not NULL */
unsigned char *radudpget(int s, struct peer **peer, struct sockaddr_storage *sa) {
    int cnt, len;
    struct peer *f;
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

	f = find_peer('U', (struct sockaddr *)&from, *peer);
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
    *peer = f; /* only need this if *peer == NULL, but if not NULL *peer == f here */
    if (sa)
	*sa = from;
    return rad;
}

void tlsconnect(struct peer *peer, struct timeval *when, char *text) {
    struct timeval now;
    time_t elapsed;
    unsigned long error;

    pthread_mutex_lock(&peer->lock);
    if (when && memcmp(&peer->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	printf("tlsconnect: seems already reconnected\n");
	pthread_mutex_unlock(&peer->lock);
	return;
    }

    printf("tlsconnect %s\n", text);

    for (;;) {
	printf("tlsconnect: trying to open TLS connection to %s port %s\n", peer->host, peer->port);
	gettimeofday(&now, NULL);
	elapsed = now.tv_sec - peer->lastconnecttry.tv_sec;
	memcpy(&peer->lastconnecttry, &now, sizeof(struct timeval));
	if (peer->connectionok) {
	    peer->connectionok = 0;
	    sleep(10);
	} else if (elapsed < 5)
	    sleep(10);
	else if (elapsed < 600)
	    sleep(elapsed * 2);
	else if (elapsed < 10000) /* no sleep at startup */
		sleep(900);
	if (peer->sockcl >= 0)
	    close(peer->sockcl);
	if ((peer->sockcl = connecttopeer(peer)) < 0)
	    continue;
	SSL_free(peer->sslcl);
	peer->sslcl = SSL_new(ssl_ctx_cl);
	SSL_set_fd(peer->sslcl, peer->sockcl);
	if (SSL_connect(peer->sslcl) > 0)
	    break;
	while ((error = ERR_get_error()))
	    err("tlsconnect: TLS: %s", ERR_error_string(error, NULL));
    }
    printf("tlsconnect: TLS connection to %s port %s up\n", peer->host, peer->port);
    pthread_mutex_unlock(&peer->lock);
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

int clientradput(struct peer *peer, unsigned char *rad) {
    int cnt;
    size_t len;
    unsigned long error;
    struct timeval lastconnecttry;
    
    len = RADLEN(rad);
    if (peer->type == 'U') {
	if (send(peer->sockcl, rad, len, 0) >= 0) {
	    printf("clienradput: sent UDP of length %d to %s port %s\n", len, peer->host, peer->port);
	    return 1;
	}
	err("clientradput: send failed");
	return 0;
    }

    lastconnecttry = peer->lastconnecttry;
    while ((cnt = SSL_write(peer->sslcl, rad, len)) <= 0) {
	while ((error = ERR_get_error()))
	    err("clientwr: TLS: %s", ERR_error_string(error, NULL));
	tlsconnect(peer, &lastconnecttry, "clientradput");
	lastconnecttry = peer->lastconnecttry;
    }

    peer->connectionok = 1;
    printf("clientradput: Sent %d bytes, Radius packet of length %d to TLS peer %s\n",
	   cnt, len, peer->host);
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
	      
void sendrq(struct peer *to, struct peer *from, struct request *rq) {
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

void sendreply(struct peer *to, struct peer *from, char *buf, struct sockaddr_storage *tosa) {
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

struct peer *id2peer(char *id, uint8_t len) {
    int i;
    char **realm;

    for (i = 0; i < peer_count; i++) {
	for (realm = peers[i].realms; *realm; realm++) {
	    /* assume test@domain */
	    printf("realmlength %d, usernamelenght %d\n", strlen(*realm), len);
	    if (strlen(*realm) == len && !memcmp(id + 5, *realm, len - 5)) {
		printf("found matching realm: %s, host %s\n", *realm, peers[i].host);
		return peers + i;
	    }
	}
    }
    return NULL;
}

struct peer *radsrv(struct request *rq, char *buf, struct peer *from) {
    uint8_t code, id, *auth, *attr, *usernameattr = NULL, *userpwdattr = NULL, pwd[128], pwdlen;
    int i;
    uint16_t len;
    int left;
    struct peer *to;
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

    /* find out where to send the packet, for now we send to first connected
       TLS peer if UDP, and first UDP peer if TLS */

    to = id2peer(&usernameattr[RAD_Attr_Value], usernameattr[RAD_Attr_Length] - 2);
    if (!to) {
	printf("radsrv: ignoring request, don't know where to send it\n");
	return NULL;
    }

#if 0    
    i = peer_count;
    
    switch (from->type) {
    case 'U':
	for (i = 0; i < peer_count; i++)
	    if (peers[i].type == 'T' && peers[i].sockcl >= 0)
		break;
	break;
    case 'T':
	for (i = 0; i < peer_count; i++)
	    if (peers[i].type == 'U')
		break;
	break;
    }
    if (i == peer_count) {
	printf("radsrv: ignoring request, don't know where to send it\n");
	return NULL;
    }

    to = &peers[i];
    
#endif
		 
    if (!RAND_bytes(newauth, 16)) {
	printf("radsrv: failed to generate random auth\n");
	return NULL;
    }

    if (userpwdattr) {
	printf("radsrv: found userpwdattr of length %d\n", userpwdattr[RAD_Attr_Length]);
	pwdlen = userpwdattr[RAD_Attr_Length] - 2;
	if (pwdlen < 16 || pwdlen > 128 || pwdlen % 16) {
	    printf("radsrv: invalid user password length\n");
	    return NULL;
	}
	
	if (!pwdcrypt(pwd, &userpwdattr[RAD_Attr_Value], pwdlen, from->secret, strlen(from->secret), auth)) {
	    printf("radsrv: cannot decrypt password\n");
	    return NULL;
	}
	printf("radsrv: password: ");
	for (i = 0; i < pwdlen; i++)
	    printf("%02x ", pwd[i]);
	printf("\n");
	if (!pwdcrypt(&userpwdattr[RAD_Attr_Value], pwd, pwdlen, to->secret, strlen(to->secret), newauth)) {
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
    struct peer *from, *peer = (struct peer *)arg;
    int i;
    unsigned char *buf;
    struct sockaddr_storage fromsa;
    struct timeval lastconnecttry;
    
    for (;;) {
	lastconnecttry = peer->lastconnecttry;
	buf = (peer->type == 'U' ? radudpget(peer->sockcl, &peer, NULL) : radtlsget(peer->sslcl));
	if (!buf && peer->type == 'T') {
	    tlsconnect(peer, &lastconnecttry, "clientrd");
	    continue;
	}

	peer->connectionok = 1;
	
	i = buf[1]; /* i is the id */

	pthread_mutex_lock(&peer->newrq_mutex);
	if (!peer->requests[i].buf || !peer->requests[i].tries) {
	    pthread_mutex_unlock(&peer->newrq_mutex);
	    printf("clientrd: no matching request sent with this id, ignoring\n");
	    continue;
	}
        
	if (peer->requests[i].received) {
	    pthread_mutex_unlock(&peer->newrq_mutex);
	    printf("clientrd: already received, ignoring\n");
	    continue;
	}

	if (!validauth(buf, peer->requests[i].buf + 4, peer->secret)) {
	    pthread_mutex_unlock(&peer->newrq_mutex);
	    printf("clientrd: invalid auth, ignoring\n");
	    continue;
	}

	/* once we set received = 1, requests[i] may be reused */
	buf[1] = (char)peer->requests[i].origid;
	memcpy(buf + 4, peer->requests[i].origauth, 16);
	from = peer->requests[i].from;
	if (from->type == 'U')
	    fromsa = peer->requests[i].fromsa;
	peer->requests[i].received = 1;
	pthread_mutex_unlock(&peer->newrq_mutex);

	if (!radsign(buf, from->secret)) {
	    printf("clientrd: failed to sign message\n");
	    continue;
	}
	
	printf("clientrd: giving packet back to where it came from\n");
	sendreply(from, peer, buf, from->type == 'U' ? &fromsa : NULL);
    }
}

void *clientwr(void *arg) {
    struct peer *peer = (struct peer *)arg;
    pthread_t clientrdth;
    int i;

    if (peer->type == 'U') {
	if ((peer->sockcl = connecttopeer(peer)) < 0) {
	    printf("clientwr: connecttopeer failed\n");
	    exit(1);
	}
    } else
	tlsconnect(peer, NULL, "new client");
    
    if (pthread_create(&clientrdth, NULL, clientrd, (void *)peer))
	errx("clientwr: pthread_create failed");

    for (;;) {
	pthread_mutex_lock(&peer->newrq_mutex);
	while (!peer->newrq) {
	    printf("clientwr: waiting for signal\n");
	    pthread_cond_wait(&peer->newrq_cond, &peer->newrq_mutex);
	    printf("clientwr: got signal\n");
	}
	peer->newrq = 0;
	pthread_mutex_unlock(&peer->newrq_mutex);
	       
	for (i = 0; i < MAX_REQUESTS; i++) {
	    pthread_mutex_lock(&peer->newrq_mutex);
	    while (!peer->requests[i].buf && i < MAX_REQUESTS)
		i++;
	    if (i == MAX_REQUESTS) {
		pthread_mutex_unlock(&peer->newrq_mutex);
		break;
	    }

	    /* already received or too many tries */
            if (peer->requests[i].received || peer->requests[i].tries > 2) {
                free(peer->requests[i].buf);
                /* setting this to NULL means that it can be reused */
                peer->requests[i].buf = NULL;
                pthread_mutex_unlock(&peer->newrq_mutex);
                continue;
            }
            pthread_mutex_unlock(&peer->newrq_mutex);
            
            peer->requests[i].tries++;
	    clientradput(peer, peer->requests[i].buf);
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
    struct peer *to, *fr;
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
	buf = radudpget(udp_server_sock, &fr, &rq.fromsa);
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
    struct peer *peer = (struct peer *)arg;
    struct replyq *replyq;
    
    pthread_mutex_lock(&peer->replycount_mutex);
    for (;;) {
	replyq = peer->replyq;
	while (!replyq->count) {
	    printf("tls server writer, waiting for signal\n");
	    pthread_cond_wait(&replyq->count_cond, &replyq->count_mutex);
	    printf("tls server writer, got signal\n");
	}
	pthread_mutex_unlock(&replyq->count_mutex);
	cnt = SSL_write(peer->sslsrv, replyq->replies->buf, RADLEN(replyq->replies->buf));
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
    struct peer *to;
    int s;
    struct peer *peer = (struct peer *)arg;
    pthread_t tlsserverwrth;

    printf("tlsserverrd starting\n");
    if (SSL_accept(peer->sslsrv) <= 0) {
        while ((error = ERR_get_error()))
            err("tlsserverrd: SSL: %s", ERR_error_string(error, NULL));
        errx("accept failed, child exiting");
    }

    if (pthread_create(&tlsserverwrth, NULL, tlsserverwr, (void *)peer))
	errx("pthread_create failed");
    
    for (;;) {
	buf = radtlsget(peer->sslsrv);
	if (!buf) {
	    printf("tlsserverrd: connection lost\n");
	    s = SSL_get_fd(peer->sslsrv);
	    SSL_free(peer->sslsrv);
	    peer->sslsrv = NULL;
	    if (s >= 0)
		close(s);
	    pthread_exit(NULL);
	}
	printf("tlsserverrd: got Radius message from %s\n", peer->host);
	memset(&rq, 0, sizeof(struct request));
	to = radsrv(&rq, buf, peer);
	if (!to) {
	    printf("ignoring request, no place to send it\n");
	    continue;
	}
	sendrq(to, peer, &rq);
    }
}

int tlslistener(SSL_CTX *ssl_ctx) {
    pthread_t tlsserverth;
    int s, snew;
    struct sockaddr_storage from;
    size_t fromlen = sizeof(from);
    struct peer *peer;

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

	peer = find_peer('T', (struct sockaddr *)&from, NULL);
	if (!peer) {
	    printf("ignoring request, not a known TLS peer\n");
	    close(snew);
	    continue;
	}

	if (peer->sslsrv) {
	    printf("Ignoring incoming connection, already have one from this peer\n");
	    close(snew);
	    continue;
	}
	peer->sslsrv = SSL_new(ssl_ctx);
	SSL_set_fd(peer->sslsrv, snew);
	if (pthread_create(&tlsserverth, NULL, tlsserverrd, (void *)peer))
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
char *parserealmlist(char *s, struct peer *peer) {
    char *p;
    int i, n, l;

    for (p = s, n = 1; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++)
	if (*p == ';')
	    n++;
    l = p - s;
    if (!l) {
	peer->realms = NULL;
	return p;
    }
    peer->realmdata = malloc(l + 1);
    if (!peer->realmdata)
	errx("malloc failed");
    memcpy(peer->realmdata, s, l);
    peer->realmdata[l] = '\0';
    peer->realms = malloc((1+n) * sizeof(char *));
    if (!peer->realms)
	errx("malloc failed");
    peer->realms[0] = peer->realmdata;
    for (n = 1, i = 0; i < l; i++)
	if (peer->realmdata[i] == ';') {
	    peer->realmdata[i] = '\0';
	    peer->realms[n++] = peer->realmdata + i + 1;
	}	
    peer->realms[n] = NULL;
    return p;
}

void getconfig(const char *filename) {
    FILE *f;
    char line[1024];
    char *p, *field, **r;
    struct peer *peer;
    
    peer_count = 0;
    
    udp_server_replyq.replies = malloc(4 * MAX_REQUESTS * sizeof(struct reply));
    if (!udp_server_replyq.replies)
	errx("malloc failed");
    udp_server_replyq.size = 4 * MAX_REQUESTS;
    udp_server_replyq.count = 0;
    pthread_mutex_init(&udp_server_replyq.count_mutex, NULL);
    pthread_cond_init(&udp_server_replyq.count_cond, NULL);
    
    f = fopen(filename, "r");
    if (!f)
	errx("getconfig failed to open %s for reading", filename);

    while (fgets(line, 1024, f) && peer_count < MAX_PEERS) {
	peer = &peers[peer_count];
	memset(peer, 0, sizeof(struct peer));

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
	p = parserealmlist(p, peer);
	if (!peer->realms) {
	    printf("realm list must be specified\n");
	    exit(1);
	}
	for (; *p == ' ' || *p == '\t'; p++);
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
	peer->sockcl = -1;
	pthread_mutex_init(&peer->lock, NULL);
	if (!resolvepeer(peer)) {
	    printf("failed to resolve host %s port %s, exiting\n", peer->host, peer->port);
	    exit(1);
	}
	peer->requests = malloc(MAX_REQUESTS * sizeof(struct request));
	if (!peer->requests)
	    errx("malloc failed");
	memset(peer->requests, 0, MAX_REQUESTS * sizeof(struct request));
	peer->newrq = 0;
	pthread_mutex_init(&peer->newrq_mutex, NULL);
	pthread_cond_init(&peer->newrq_cond, NULL);

	if (peer->type == 'U')
	    peer->replyq = &udp_server_replyq;
	else {
	    peer->replyq = malloc(sizeof(struct replyq));
	    if (!peer->replyq)
		errx("malloc failed");
	    peer->replyq->replies = malloc(MAX_REQUESTS * sizeof(struct reply));
	    if (!peer->replyq->replies)
		errx("malloc failed");
	    peer->replyq->size = MAX_REQUESTS;
	    peer->replyq->count = 0;
	    pthread_mutex_init(&peer->replyq->count_mutex, NULL);
	    pthread_cond_init(&peer->replyq->count_cond, NULL);
	}
	printf("got type %c, host %s, port %s, secret %s\n", peers[peer_count].type,
	       peers[peer_count].host, peers[peer_count].port, peers[peer_count].secret);
	printf("    with realms:");
	for (r = peer->realms; *r; r++)
	    printf(" %s", *r);
	printf("\n");
	peer_count++;
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
    getconfig("radsecproxy.conf");
    
    ssl_locks_setup();

    pthread_attr_init(&joinable);
    pthread_attr_setdetachstate(&joinable, PTHREAD_CREATE_JOINABLE);
   
    /* listen on UDP if at least one UDP peer */
    
    for (i = 0; i < peer_count; i++)
	if (peers[i].type == 'U') {
	    if (pthread_create(&udpserverth, &joinable, udpserverrd, NULL))
		errx("pthread_create failed");
	    break;
	}
    
    for (i = 0; i < peer_count; i++)
	if (peers[i].type == 'T')
	    break;

    if (i == peer_count) {
	printf("No TLS peers defined, just doing UDP proxying\n");
	/* just hang around doing nothing, anything to do here? */
	pthread_join(udpserverth, NULL);
	return 0;
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
    
    for (i = 0; i < peer_count; i++) {
	if (pthread_create(&peers[i].clientth, NULL, clientwr, (void *)&peers[i]))
	    errx("pthread_create failed");
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
