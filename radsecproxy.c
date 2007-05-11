/*
 * Copyright (C) 2006, 2007 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

/* TODO:
 * accounting
 * radius keep alives (server status)
 * setsockopt(keepalive...), check if openssl has some keepalive feature
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <libgen.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include "debug.h"
#include "radsecproxy.h"

static struct options options;
static struct client *clients;
static struct server *servers;

static int client_udp_count = 0;
static int client_tls_count = 0;
static int client_count = 0;
static int server_udp_count = 0;
static int server_tls_count = 0;
static int server_count = 0;

static struct peer *tcp_server_listen;
static struct peer *udp_server_listen;
static struct replyq udp_server_replyq;
static int udp_server_sock = -1;
static pthread_mutex_t *ssl_locks;
static long *ssl_lock_count;
static SSL_CTX *ssl_ctx = NULL;
extern int optind;
extern char *optarg;

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

static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    int pwdlen = strlen(userdata);
    if (rwflag != 0 || pwdlen > size) /* not for decryption or too large */
	return 0;
    memcpy(buf, userdata, pwdlen);
    return pwdlen;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx) {
  char buf[256];
  X509 *err_cert;
  int err, depth;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  if (depth > MAX_CERT_DEPTH) {
      ok = 0;
      err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
      X509_STORE_CTX_set_error(ctx, err);
  }

  if (!ok) {
      X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
      debug(DBG_WARN, "verify error: num=%d:%s:depth=%d:%s", err, X509_verify_cert_error_string(err), depth, buf);

      switch (err) {
      case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	  X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
	  debug(DBG_WARN, "\tIssuer=%s", buf);
	  break;
      case X509_V_ERR_CERT_NOT_YET_VALID:
      case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	  debug(DBG_WARN, "\tCertificate not yet valid");
	  break;
      case X509_V_ERR_CERT_HAS_EXPIRED:
	  debug(DBG_WARN, "Certificate has expired");
	  break;
      case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	  debug(DBG_WARN, "Certificate no longer valid (after notAfter)");
	  break;
      }
  }
#ifdef DEBUG  
  printf("certificate verify returns %d\n", ok);
#endif  
  return ok;
}

SSL_CTX *ssl_init() {
    SSL_CTX *ctx;
    int i;
    unsigned long error;
    
    if (!options.tlscertificatefile || !options.tlscertificatekeyfile)
	debugx(1, DBG_ERR, "TLSCertificateFile and TLSCertificateKeyFile must be specified for TLS");

    if (!options.tlscacertificatefile && !options.tlscacertificatepath)
	debugx(1, DBG_ERR, "CA Certificate file/path need to be configured");

    ssl_locks = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
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
	time_t t = time(NULL);
	pid_t pid = getpid();
	RAND_seed((unsigned char *)&t, sizeof(time_t));
        RAND_seed((unsigned char *)&pid, sizeof(pid));
    }

    ctx = SSL_CTX_new(TLSv1_method());
    if (options.tlscertificatekeypassword) {
	SSL_CTX_set_default_passwd_cb_userdata(ctx, options.tlscertificatekeypassword);
	SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, options.tlscertificatefile) &&
	SSL_CTX_use_PrivateKey_file(ctx, options.tlscertificatekeyfile, SSL_FILETYPE_PEM) &&
	SSL_CTX_check_private_key(ctx) &&
	SSL_CTX_load_verify_locations(ctx, options.tlscacertificatefile, options.tlscacertificatepath)) {
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
	SSL_CTX_set_verify_depth(ctx, MAX_CERT_DEPTH + 1);
	return ctx;
    }

    while ((error = ERR_get_error()))
	debug(DBG_ERR, "SSL: %s", ERR_error_string(error, NULL));
    debug(DBG_ERR, "Error initialising SSL/TLS");
    exit(1);
}    

#ifdef DEBUG
void printauth(char *s, unsigned char *t) {
    int i;
    printf("%s:", s);
    for (i = 0; i < 16; i++)
	    printf("%02x ", t[i]);
    printf("\n");
}
#endif

int resolvepeer(struct peer *peer, int ai_flags) {
    struct addrinfo hints, *addrinfo;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = (peer->type == 'T' ? SOCK_STREAM : SOCK_DGRAM);
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = ai_flags;
    if (getaddrinfo(peer->host, peer->port, &hints, &addrinfo)) {
	debug(DBG_WARN, "resolvepeer: can't resolve %s port %s", peer->host, peer->port);
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
            debug(DBG_WARN, "connecttoserver: socket failed");
            continue;
        }
        if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
            break;
        debug(DBG_WARN, "connecttoserver: connect failed");
        close(s);
        s = -1;
    }
    return s;
}	  

int bindtoaddr(struct addrinfo *addrinfo) {
    int s, on = 1;
    struct addrinfo *res;
    
    for (res = addrinfo; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            debug(DBG_WARN, "bindtoaddr: socket failed");
            continue;
        }
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (!bind(s, res->ai_addr, res->ai_addrlen))
	    return s;
	debug(DBG_WARN, "bindtoaddr: bind failed");
        close(s);
    }
    return -1;
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
	    debug(DBG_WARN, "radudpget: recv failed");
	    continue;
	}
	debug(DBG_DBG, "radudpget: got %d bytes from %s", cnt, addr2string((struct sockaddr *)&from, fromlen));

	if (cnt < 20) {
	    debug(DBG_WARN, "radudpget: packet too small");
	    continue;
	}
    
	len = RADLEN(buf);
	if (len < 20) {
	    debug(DBG_WARN, "radudpget: length too small");
	    continue;
	}

	if (cnt < len) {
	    debug(DBG_WARN, "radudpget: packet smaller than length field in radius header");
	    continue;
	}
	if (cnt > len)
	    debug(DBG_DBG, "radudpget: packet was padded with %d bytes", cnt - len);

	f = (client
	     ? (void *)find_client('U', (struct sockaddr *)&from, *client)
	     : (void *)find_server('U', (struct sockaddr *)&from, *server));
	if (!f) {
	    debug(DBG_WARN, "radudpget: got packet from wrong or unknown UDP peer, ignoring");
	    continue;
	}

	rad = malloc(len);
	if (rad)
	    break;
	debug(DBG_ERR, "radudpget: malloc failed");
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

int tlsverifycert(struct peer *peer) {
    int l, loc;
    X509 *cert;
    X509_NAME *nm;
    X509_NAME_ENTRY *e;
    unsigned char *v;
    unsigned long error;

    if (SSL_get_verify_result(peer->ssl) != X509_V_OK) {
	debug(DBG_ERR, "tlsverifycert: basic validation failed");
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "tlsverifycert: TLS: %s", ERR_error_string(error, NULL));
	return 0;
    }

    cert = SSL_get_peer_certificate(peer->ssl);
    if (!cert) {
	debug(DBG_ERR, "tlsverifycert: failed to obtain certificate");
	return 0;
    }
    nm = X509_get_subject_name(cert);
    loc = -1;
    for (;;) {
	loc = X509_NAME_get_index_by_NID(nm, NID_commonName, loc);
	if (loc == -1)
	    break;
	e = X509_NAME_get_entry(nm, loc);
	l = ASN1_STRING_to_UTF8(&v, X509_NAME_ENTRY_get_data(e));
	if (l < 0)
	    continue;
#ifdef DEBUG
	{
	    int i;
	    printf("cn: ");
	    for (i = 0; i < l; i++)
		printf("%c", v[i]);
	    printf("\n");
	}
#endif	
	if (l == strlen(peer->host) && !strncasecmp(peer->host, (char *)v, l)) {
	    debug(DBG_DBG, "tlsverifycert: Found cn matching host %s, All OK", peer->host);
	    return 1;
	}
	debug(DBG_ERR, "tlsverifycert: cn not matching host %s", peer->host);
    }
    X509_free(cert);
    return 0;
}

void tlsconnect(struct server *server, struct timeval *when, char *text) {
    struct timeval now;
    time_t elapsed;

    debug(DBG_DBG, "tlsconnect called from %s", text);
    pthread_mutex_lock(&server->lock);
    if (when && memcmp(&server->lastconnecttry, when, sizeof(struct timeval))) {
	/* already reconnected, nothing to do */
	debug(DBG_DBG, "tlsconnect(%s): seems already reconnected", text);
	pthread_mutex_unlock(&server->lock);
	return;
    }

    debug(DBG_DBG, "tlsconnect %s", text);

    for (;;) {
	gettimeofday(&now, NULL);
	elapsed = now.tv_sec - server->lastconnecttry.tv_sec;
	if (server->connectionok) {
	    server->connectionok = 0;
	    sleep(10);
	} else if (elapsed < 5)
	    sleep(10);
	else if (elapsed < 600) {
	    debug(DBG_INFO, "tlsconnect: sleeping %lds", elapsed);
	    sleep(elapsed);
	} else if (elapsed < 1000) {
	    debug(DBG_INFO, "tlsconnect: sleeping %ds", 900);
	    sleep(900);
	} else
	    server->lastconnecttry.tv_sec = now.tv_sec;  /* no sleep at startup */
	debug(DBG_WARN, "tlsconnect: trying to open TLS connection to %s port %s", server->peer.host, server->peer.port);
	if (server->sock >= 0)
	    close(server->sock);
	if ((server->sock = connecttoserver(server->peer.addrinfo)) < 0) {
	    debug(DBG_ERR, "tlsconnect: connecttoserver failed");
	    continue;
	}
	
	SSL_free(server->peer.ssl);
	server->peer.ssl = SSL_new(ssl_ctx);
	SSL_set_fd(server->peer.ssl, server->sock);
	if (SSL_connect(server->peer.ssl) > 0 && tlsverifycert(&server->peer))
	    break;
    }
    debug(DBG_WARN, "tlsconnect: TLS connection to %s port %s up", server->peer.host, server->peer.port);
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
		debug(DBG_ERR, "radtlsget: connection lost");
		if (SSL_get_error(ssl, cnt) == SSL_ERROR_ZERO_RETURN) {
		    /* remote end sent close_notify, send one back */
		    SSL_shutdown(ssl);
		}
		return NULL;
	    }
	}

	len = RADLEN(buf);
	rad = malloc(len);
	if (!rad) {
	    debug(DBG_ERR, "radtlsget: malloc failed");
	    continue;
	}
	memcpy(rad, buf, 4);

	for (; total < len; total += cnt) {
	    cnt = SSL_read(ssl, rad + total, len - total);
	    if (cnt <= 0) {
		debug(DBG_ERR, "radtlsget: connection lost");
		if (SSL_get_error(ssl, cnt) == SSL_ERROR_ZERO_RETURN) {
		    /* remote end sent close_notify, send one back */
		    SSL_shutdown(ssl);
		}
		free(rad);
		return NULL;
	    }
	}
    
	if (total >= 20)
	    break;
	
	free(rad);
	debug(DBG_WARN, "radtlsget: packet smaller than minimum radius size");
    }
    
    debug(DBG_DBG, "radtlsget: got %d bytes", total);
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
	    debug(DBG_DBG, "clienradput: sent UDP of length %d to %s port %s", len, server->peer.host, server->peer.port);
	    return 1;
	}
	debug(DBG_WARN, "clientradput: send failed");
	return 0;
    }

    lastconnecttry = server->lastconnecttry;
    while ((cnt = SSL_write(server->peer.ssl, rad, len)) <= 0) {
	while ((error = ERR_get_error()))
	    debug(DBG_ERR, "clientradput: TLS: %s", ERR_error_string(error, NULL));
	tlsconnect(server, &lastconnecttry, "clientradput");
	lastconnecttry = server->lastconnecttry;
    }

    server->connectionok = 1;
    debug(DBG_DBG, "clientradput: Sent %d bytes, Radius packet of length %d to TLS peer %s",
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
	EVP_DigestUpdate(&mdctx, sec, strlen((char *)sec)) &&
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
	      EVP_DigestUpdate(&mdctx, sec, strlen((char *)sec)) &&
	      EVP_DigestFinal_ex(&mdctx, hash, &len) &&
	      len == 16 &&
	      !memcmp(hash, rad + 4, 16));
    pthread_mutex_unlock(&lock);
    return result;
}
	      
int checkmessageauth(unsigned char *rad, uint8_t *authattr, char *secret) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static HMAC_CTX hmacctx;
    unsigned int md_len;
    uint8_t auth[16], hash[EVP_MAX_MD_SIZE];
    
    pthread_mutex_lock(&lock);
    if (first) {
	HMAC_CTX_init(&hmacctx);
	first = 0;
    }

    memcpy(auth, authattr, 16);
    memset(authattr, 0, 16);
    md_len = 0;
    HMAC_Init_ex(&hmacctx, secret, strlen(secret), EVP_md5(), NULL);
    HMAC_Update(&hmacctx, rad, RADLEN(rad));
    HMAC_Final(&hmacctx, hash, &md_len);
    memcpy(authattr, auth, 16);
    if (md_len != 16) {
	debug(DBG_WARN, "message auth computation failed");
	pthread_mutex_unlock(&lock);
	return 0;
    }

    if (memcmp(auth, hash, 16)) {
	debug(DBG_WARN, "message authenticator, wrong value");
	pthread_mutex_unlock(&lock);
	return 0;
    }	
	
    pthread_mutex_unlock(&lock);
    return 1;
}

int createmessageauth(unsigned char *rad, unsigned char *authattrval, char *secret) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static unsigned char first = 1;
    static HMAC_CTX hmacctx;
    unsigned int md_len;

    if (!authattrval)
	return 1;
    
    pthread_mutex_lock(&lock);
    if (first) {
	HMAC_CTX_init(&hmacctx);
	first = 0;
    }

    memset(authattrval, 0, 16);
    md_len = 0;
    HMAC_Init_ex(&hmacctx, secret, strlen(secret), EVP_md5(), NULL);
    HMAC_Update(&hmacctx, rad, RADLEN(rad));
    HMAC_Final(&hmacctx, authattrval, &md_len);
    if (md_len != 16) {
	debug(DBG_WARN, "message auth computation failed");
	pthread_mutex_unlock(&lock);
	return 0;
    }

    pthread_mutex_unlock(&lock);
    return 1;
}

unsigned char *attrget(unsigned char *attrs, int length, uint8_t type, uint8_t *len) {
    while (length > 1) {
	if (attrs[RAD_Attr_Type] == type) {
	    if (len)
		*len = attrs[RAD_Attr_Length] - 2;
	    return &attrs[RAD_Attr_Value];
	}
	length -= attrs[RAD_Attr_Length];
	attrs += attrs[RAD_Attr_Length];
    }
    return NULL;
}

void sendrq(struct server *to, struct client *from, struct request *rq) {
    int i;
    uint8_t *attrval;
    
    pthread_mutex_lock(&to->newrq_mutex);
    /* might simplify if only try nextid, might be ok */
    for (i = to->nextid; i < MAX_REQUESTS; i++)
	if (!to->requests[i].buf)
	    break;
    if (i == MAX_REQUESTS) {
	for (i = 0; i < to->nextid; i++)
	    if (!to->requests[i].buf)
		break;
	if (i == to->nextid) {
	    debug(DBG_WARN, "No room in queue, dropping request");
	    pthread_mutex_unlock(&to->newrq_mutex);
	    return;
	}
    }
    
    to->nextid = i + 1;
    rq->buf[1] = (char)i;
    debug(DBG_DBG, "sendrq: inserting packet with id %d in queue for %s", i, to->peer.host);

    attrval = attrget(rq->buf + 20, RADLEN(rq->buf) - 20, RAD_Attr_Message_Authenticator, NULL);
    if (attrval && !createmessageauth(rq->buf, attrval, to->peer.secret))
	return;

    to->requests[i] = *rq;

    if (!to->newrq) {
	to->newrq = 1;
	debug(DBG_DBG, "signalling client writer");
	pthread_cond_signal(&to->newrq_cond);
    }
    pthread_mutex_unlock(&to->newrq_mutex);
}

void sendreply(struct client *to, struct server *from, unsigned char *buf, struct sockaddr_storage *tosa) {
    struct replyq *replyq = to->replyq;
    
    pthread_mutex_lock(&replyq->count_mutex);
    if (replyq->count == replyq->size) {
	debug(DBG_WARN, "No room in queue, dropping request");
	pthread_mutex_unlock(&replyq->count_mutex);
	return;
    }

    replyq->replies[replyq->count].buf = buf;
    if (tosa)
	replyq->replies[replyq->count].tosa = *tosa;
    replyq->count++;

    if (replyq->count == 1) {
	debug(DBG_DBG, "signalling client writer");
	pthread_cond_signal(&replyq->count_cond);
    }
    pthread_mutex_unlock(&replyq->count_mutex);
}

int pwdencrypt(uint8_t *in, uint8_t len, char *shared, uint8_t sharedlen, uint8_t *auth) {
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
	input = out + offset - 16;
	offset += 16;
	if (offset == len)
	    break;
    }
    memcpy(in, out, len);
    pthread_mutex_unlock(&lock);
    return 1;
}

int pwddecrypt(uint8_t *in, uint8_t len, char *shared, uint8_t sharedlen, uint8_t *auth) {
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
    printf("msppencrypt auth in: ");
    for (i = 0; i < 16; i++)
	printf("%02x ", auth[i]);
    printf("\n");
    
    printf("msppencrypt salt in: ");
    for (i = 0; i < 2; i++)
	printf("%02x ", salt[i]);
    printf("\n");
    
    printf("msppencrypt in: ");
    for (i = 0; i < len; i++)
	printf("%02x ", text[i]);
    printf("\n");
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
    printf("msppencrypt hash: ");
    for (i = 0; i < 16; i++)
	printf("%02x ", hash[i]);
    printf("\n");
#endif
    
    for (i = 0; i < 16; i++)
	text[i] ^= hash[i];
    
    for (offset = 16; offset < len; offset += 16) {
#if 0	
	printf("text + offset - 16 c(%d): ", offset / 16);
	for (i = 0; i < 16; i++)
	    printf("%02x ", (text + offset - 16)[i]);
	printf("\n");
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
	printf("msppencrypt hash: ");
	for (i = 0; i < 16; i++)
	    printf("%02x ", hash[i]);
	printf("\n");
#endif    
	
	for (i = 0; i < 16; i++)
	    text[offset + i] ^= hash[i];
    }
    
#if 0
    printf("msppencrypt out: ");
    for (i = 0; i < len; i++)
	printf("%02x ", text[i]);
    printf("\n");
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
    printf("msppdecrypt auth in: ");
    for (i = 0; i < 16; i++)
	printf("%02x ", auth[i]);
    printf("\n");
    
    printf("msppedecrypt salt in: ");
    for (i = 0; i < 2; i++)
	printf("%02x ", salt[i]);
    printf("\n");
    
    printf("msppedecrypt in: ");
    for (i = 0; i < len; i++)
	printf("%02x ", text[i]);
    printf("\n");
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
    printf("msppedecrypt hash: ");
    for (i = 0; i < 16; i++)
	printf("%02x ", hash[i]);
    printf("\n");
#endif
    
    for (i = 0; i < 16; i++)
	plain[i] = text[i] ^ hash[i];
    
    for (offset = 16; offset < len; offset += 16) {
#if 0 	
	printf("text + offset - 16 c(%d): ", offset / 16);
	for (i = 0; i < 16; i++)
	    printf("%02x ", (text + offset - 16)[i]);
	printf("\n");
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
    printf("msppedecrypt hash: ");
    for (i = 0; i < 16; i++)
	printf("%02x ", hash[i]);
    printf("\n");
#endif    

    for (i = 0; i < 16; i++)
	plain[offset + i] = text[offset + i] ^ hash[i];
    }

    memcpy(text, plain, len);
#if 0
    printf("msppedecrypt out: ");
    for (i = 0; i < len; i++)
	printf("%02x ", text[i]);
    printf("\n");
#endif

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
		debug(DBG_DBG, "found matching realm: %s, host %s", *realm, servers[i].peer.host);
		return servers + i;
	    }
	}
    }
    return NULL;
}

int rqinqueue(struct server *to, struct client *from, uint8_t id) {
    int i;
    
    pthread_mutex_lock(&to->newrq_mutex);
    for (i = 0; i < MAX_REQUESTS; i++)
	if (to->requests[i].buf && to->requests[i].origid == id && to->requests[i].from == from)
	    break;
    pthread_mutex_unlock(&to->newrq_mutex);
    
    return i < MAX_REQUESTS;
}

int attrvalidate(unsigned char *attrs, int length) {
    while (length > 1) {
	if (attrs[RAD_Attr_Length] < 2) {
	    debug(DBG_WARN, "attrvalidate: invalid attribute length %d", attrs[RAD_Attr_Length]);
	    return 0;
	}
	length -= attrs[RAD_Attr_Length];
	if (length < 0) {
	    debug(DBG_WARN, "attrvalidate: attribute length %d exceeds packet length", attrs[RAD_Attr_Length]);
	    return 0;
	}
	attrs += attrs[RAD_Attr_Length];
    }
    if (length)
	debug(DBG_WARN, "attrvalidate: malformed packet? remaining byte after last attribute");
    return 1;
}

int pwdrecrypt(uint8_t *pwd, uint8_t len, char *oldsecret, char *newsecret, uint8_t *oldauth, uint8_t *newauth) {
#ifdef DEBUG    
    int i;
#endif    
    if (len < 16 || len > 128 || len % 16) {
	debug(DBG_WARN, "pwdrecrypt: invalid password length");
	return 0;
    }
	
    if (!pwddecrypt(pwd, len, oldsecret, strlen(oldsecret), oldauth)) {
	debug(DBG_WARN, "pwdrecrypt: cannot decrypt password");
	return 0;
    }
#ifdef DEBUG
    printf("pwdrecrypt: password: ");
    for (i = 0; i < len; i++)
	printf("%02x ", pwd[i]);
    printf("\n");
#endif	
    if (!pwdencrypt(pwd, len, newsecret, strlen(newsecret), newauth)) {
	debug(DBG_WARN, "pwdrecrypt: cannot encrypt password");
	return 0;
    }
    return 1;
}

int msmpprecrypt(uint8_t *msmpp, uint8_t len, char *oldsecret, char *newsecret, unsigned char *oldauth, char *newauth) {
    if (len < 18)
	return 0;
    if (!msmppdecrypt(msmpp + 2, len - 2, (unsigned char *)oldsecret, strlen(oldsecret), oldauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to decrypt msppe key");
	return 0;
    }
    if (!msmppencrypt(msmpp + 2, len - 2, (unsigned char *)newsecret, strlen(newsecret), (unsigned char *)newauth, msmpp)) {
	debug(DBG_WARN, "msmpprecrypt: failed to encrypt msppe key");
	return 0;
    }
    return 1;
}

struct server *radsrv(struct request *rq, unsigned char *buf, struct client *from) {
    uint8_t code, id, *auth, *attrs, attrvallen, *attrval;
    uint16_t len;
    struct server *to;
    char username[256];
    unsigned char newauth[16];
    
    code = *(uint8_t *)buf;
    id = *(uint8_t *)(buf + 1);
    len = RADLEN(buf);
    auth = (uint8_t *)(buf + 4);

    debug(DBG_DBG, "radsrv: code %d, id %d, length %d", code, id, len);
    
    if (code != RAD_Access_Request) {
	debug(DBG_INFO, "radsrv: server currently accepts only access-requests, ignoring");
	return NULL;
    }

    len -= 20;
    attrs = buf + 20;

    if (!attrvalidate(attrs, len)) {
	debug(DBG_WARN, "radsrv: attribute validation failed, ignoring packet");
	return NULL;
    }
	
    attrval = attrget(attrs, len, RAD_Attr_User_Name, &attrvallen);
    if (!attrval) {
	debug(DBG_WARN, "radsrv: ignoring request, no username attribute");
	return NULL;
    }
    memcpy(username, attrval, attrvallen);
    username[attrvallen] = '\0';
    debug(DBG_DBG, "Access Request with username: %s", username);
    
    to = id2server(username, attrvallen);
    if (!to) {
	debug(DBG_INFO, "radsrv: ignoring request, don't know where to send it");
	return NULL;
    }
    
    if (rqinqueue(to, from, id)) {
	debug(DBG_INFO, "radsrv: ignoring request from host %s with id %d, already got one", from->peer.host, id);
	return NULL;
    }

    attrval = attrget(attrs, len, RAD_Attr_Message_Authenticator, &attrvallen);
    if (attrval && (attrvallen != 16 || !checkmessageauth(buf, attrval, from->peer.secret))) {
	debug(DBG_WARN, "radsrv: message authentication failed");
	return NULL;
    }

    if (!RAND_bytes(newauth, 16)) {
	debug(DBG_WARN, "radsrv: failed to generate random auth");
	return NULL;
    }

#ifdef DEBUG    
    printauth("auth", auth);
    printauth("newauth", newauth);
#endif
    
    attrval = attrget(attrs, len, RAD_Attr_User_Password, &attrvallen);
    if (attrval) {
	debug(DBG_DBG, "radsrv: found userpwdattr with value length %d", attrvallen);
	if (!pwdrecrypt(attrval, attrvallen, from->peer.secret, to->peer.secret, auth, newauth))
	    return NULL;
    }
    
    attrval = attrget(attrs, len, RAD_Attr_Tunnel_Password, &attrvallen);
    if (attrval) {
	debug(DBG_DBG, "radsrv: found tunnelpwdattr with value length %d", attrvallen);
	if (!pwdrecrypt(attrval, attrvallen, from->peer.secret, to->peer.secret, auth, newauth))
	    return NULL;
    }

    rq->buf = buf;
    rq->from = from;
    rq->origid = id;
    memcpy(rq->origauth, auth, 16);
    memcpy(auth, newauth, 16);
#ifdef DEBUG    
    printauth("rq->origauth", (unsigned char *)rq->origauth);
    printauth("auth", auth);
#endif    
    return to;
}

void *clientrd(void *arg) {
    struct server *server = (struct server *)arg;
    struct client *from;
    int i, len, sublen;
    unsigned char *buf, *messageauth, *subattrs, *attrs, *attrval;
    uint8_t attrvallen;
    struct sockaddr_storage fromsa;
    struct timeval lastconnecttry;
    char tmp[255];
    
    for (;;) {
	lastconnecttry = server->lastconnecttry;
	buf = (server->peer.type == 'U' ? radudpget(server->sock, NULL, &server, NULL) : radtlsget(server->peer.ssl));
	if (!buf && server->peer.type == 'T') {
	    tlsconnect(server, &lastconnecttry, "clientrd");
	    continue;
	}
    
	server->connectionok = 1;

	i = buf[1]; /* i is the id */

	switch (*buf) {
	case RAD_Access_Accept:
	    debug(DBG_DBG, "got Access Accept with id %d", i);
	    break;
	case RAD_Access_Reject:
	    debug(DBG_DBG, "got Access Reject with id %d", i);
	    break;
	case RAD_Access_Challenge:
	    debug(DBG_DBG, "got Access Challenge with id %d", i);
	    break;
	default:
	    debug(DBG_INFO, "clientrd: discarding, only accept access accept, access reject and access challenge messages");
	    continue;
	}
	
	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->requests[i].buf || !server->requests[i].tries) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    debug(DBG_INFO, "clientrd: no matching request sent with this id, ignoring");
	    continue;
	}

	if (server->requests[i].received) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    debug(DBG_INFO, "clientrd: already received, ignoring");
	    continue;
	}
	
	if (!validauth(buf, server->requests[i].buf + 4, (unsigned char *)server->peer.secret)) {
	    pthread_mutex_unlock(&server->newrq_mutex);
	    debug(DBG_WARN, "clientrd: invalid auth, ignoring");
	    continue;
	}
	
	from = server->requests[i].from;
	len = RADLEN(buf) - 20;
	attrs = buf + 20;

	if (!attrvalidate(attrs, len)) {
	    debug(DBG_WARN, "clientrd: attribute validation failed, ignoring packet");
	    continue;
	}
	
	/* Message Authenticator */
	messageauth = attrget(attrs, len, RAD_Attr_Message_Authenticator, &attrvallen);
	if (messageauth) {
	    if (attrvallen != 16) {
		debug(DBG_WARN, "clientrd: illegal message auth attribute length, ignoring packet");
		continue;
	    }
	    memcpy(tmp, buf + 4, 16);
	    memcpy(buf + 4, server->requests[i].buf + 4, 16);
	    if (!checkmessageauth(buf, messageauth, server->peer.secret)) {
		debug(DBG_WARN, "clientrd: message authentication failed");
		continue;
	    }
	    memcpy(buf + 4, tmp, 16);
	    debug(DBG_DBG, "clientrd: message auth ok");
	}

	/* MS MPPE */
	attrval = attrget(attrs, len, RAD_Attr_Vendor_Specific, &attrvallen);
	if (attrval && attrvallen > 4 && ((uint16_t *)attrval)[0] == 0 && ntohs(((uint16_t *)attrval)[1]) == 311) { /* 311 == MS */
	    sublen = attrvallen - 4;
	    subattrs = attrval + 4;
	    if (!attrvalidate(subattrs, sublen)) {
		debug(DBG_WARN, "radsrv: MS attribute validation failed, ignoring packet");
		continue;
	    }
	    
	    attrval = attrget(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Send_Key, &attrvallen);
	    if (attrval) {
		debug(DBG_DBG, "clientrd: Got MS MPPE Send Key");
		if (!msmpprecrypt(attrval, attrvallen, server->peer.secret, from->peer.secret,
				  server->requests[i].buf + 4, server->requests[i].origauth))
		    continue;
	    }
	    
	    attrval = attrget(subattrs, sublen, RAD_VS_ATTR_MS_MPPE_Recv_Key, &attrvallen);
	    if (attrval) {
		debug(DBG_DBG, "clientrd: Got MS MPPE Recv Key");
		if (!msmpprecrypt(attrval, attrvallen, server->peer.secret, from->peer.secret,
				  server->requests[i].buf + 4, server->requests[i].origauth))
		    continue;
	    }
	}

	/* log DBG_INFO that received access accept/reject and username attr from original request */
	
	/* once we set received = 1, requests[i] may be reused */
	buf[1] = (char)server->requests[i].origid;
	memcpy(buf + 4, server->requests[i].origauth, 16);
#ifdef DEBUG	
	printauth("origauth/buf+4", buf + 4);
#endif
	
	if (messageauth) {
	    if (!createmessageauth(buf, messageauth, from->peer.secret))
		continue;
	    debug(DBG_DBG, "clientrd: computed messageauthattr");
	}

	if (from->peer.type == 'U')
	    fromsa = server->requests[i].fromsa;
	server->requests[i].received = 1;
	pthread_mutex_unlock(&server->newrq_mutex);

	if (!radsign(buf, (unsigned char *)from->peer.secret)) {
	    debug(DBG_WARN, "clientrd: failed to sign message");
	    continue;
	}
#ifdef DEBUG	
	printauth("signedorigauth/buf+4", buf + 4);
#endif	
	debug(DBG_DBG, "clientrd: giving packet back to where it came from");
	sendreply(from, server, buf, from->peer.type == 'U' ? &fromsa : NULL);
    }
}

void *clientwr(void *arg) {
    struct server *server = (struct server *)arg;
    struct request *rq;
    pthread_t clientrdth;
    int i;
    uint8_t rnd;
    struct timeval now, lastsend;
    struct timespec timeout;

    memset(&lastsend, 0, sizeof(struct timeval));
    memset(&timeout, 0, sizeof(struct timespec));

    if (server->peer.type == 'U') {
	if ((server->sock = connecttoserver(server->peer.addrinfo)) < 0)
	    debugx(1, DBG_ERR, "clientwr: connecttoserver failed");
    } else
	tlsconnect(server, NULL, "new client");
    
    if (pthread_create(&clientrdth, NULL, clientrd, (void *)server))
	debugx(1, DBG_ERR, "clientwr: pthread_create failed");

    for (;;) {
	pthread_mutex_lock(&server->newrq_mutex);
	if (!server->newrq) {
	    gettimeofday(&now, NULL);
	    if (timeout.tv_sec) {
		debug(DBG_DBG, "clientwr: waiting up to %ld secs for new request", timeout.tv_sec - now.tv_sec);
		pthread_cond_timedwait(&server->newrq_cond, &server->newrq_mutex, &timeout);
		timeout.tv_sec = 0;
	    } else if (options.statusserver) {
		timeout.tv_sec = now.tv_sec + STATUS_SERVER_PERIOD;
		/* add random 0-7 seconds to timeout */
		RAND_bytes(&rnd, 1);
		timeout.tv_sec += rnd / 32;
		pthread_cond_timedwait(&server->newrq_cond, &server->newrq_mutex, &timeout);
		timeout.tv_sec = 0;
	    } else {
		debug(DBG_DBG, "clientwr: waiting for new request");
		pthread_cond_wait(&server->newrq_cond, &server->newrq_mutex);
	    }
	}
	if (server->newrq) {
	    debug(DBG_DBG, "clientwr: got new request");
	    server->newrq = 0;
	} else
	    debug(DBG_DBG, "clientwr: request timer expired, processing request queue");
	pthread_mutex_unlock(&server->newrq_mutex);

	for (i = 0; i < MAX_REQUESTS; i++) {
	    pthread_mutex_lock(&server->newrq_mutex);
	    while (!server->requests[i].buf && i < MAX_REQUESTS)
		i++;
	    if (i == MAX_REQUESTS) {
		pthread_mutex_unlock(&server->newrq_mutex);
		break;
	    }
	    rq = server->requests + i;

            if (rq->received) {
		debug(DBG_DBG, "clientwr: removing received packet from queue");
                free(rq->buf);
                /* setting this to NULL means that it can be reused */
                rq->buf = NULL;
                pthread_mutex_unlock(&server->newrq_mutex);
                continue;
            }
	    
	    gettimeofday(&now, NULL);
            if (now.tv_sec <= rq->expiry.tv_sec) {
		if (!timeout.tv_sec || rq->expiry.tv_sec < timeout.tv_sec)
		    timeout.tv_sec = rq->expiry.tv_sec;
		pthread_mutex_unlock(&server->newrq_mutex);
		continue;
	    }

	    if (rq->tries == (server->peer.type == 'T' ? 1 : REQUEST_RETRIES)) {
		debug(DBG_DBG, "clientwr: removing expired packet from queue");
		free(rq->buf);
		/* setting this to NULL means that it can be reused */
		rq->buf = NULL;
		pthread_mutex_unlock(&server->newrq_mutex);
		continue;
	    }
            pthread_mutex_unlock(&server->newrq_mutex);

	    rq->expiry.tv_sec = now.tv_sec +
		(server->peer.type == 'T' ? REQUEST_EXPIRY : REQUEST_EXPIRY / REQUEST_RETRIES);
	    if (!timeout.tv_sec || rq->expiry.tv_sec < timeout.tv_sec)
		timeout.tv_sec = rq->expiry.tv_sec;
	    rq->tries++;
	    clientradput(server, server->requests[i].buf);
	    gettimeofday(&lastsend, NULL);
	    usleep(200000);
	}
	if (options.statusserver) {
	    gettimeofday(&now, NULL);
	    if (now.tv_sec - lastsend.tv_sec >= STATUS_SERVER_PERIOD) {
		lastsend.tv_sec = now.tv_sec;
		debug(DBG_DBG, "clientwr: should send status to %s here", server->peer.host);
	    }
	}
    }
}

void *udpserverwr(void *arg) {
    struct replyq *replyq = &udp_server_replyq;
    struct reply *reply = replyq->replies;
    
    pthread_mutex_lock(&replyq->count_mutex);
    for (;;) {
	while (!replyq->count) {
	    debug(DBG_DBG, "udp server writer, waiting for signal");
	    pthread_cond_wait(&replyq->count_cond, &replyq->count_mutex);
	    debug(DBG_DBG, "udp server writer, got signal");
	}
	pthread_mutex_unlock(&replyq->count_mutex);
	
	if (sendto(udp_server_sock, reply->buf, RADLEN(reply->buf), 0,
		   (struct sockaddr *)&reply->tosa, SOCKADDR_SIZE(reply->tosa)) < 0)
	    debug(DBG_WARN, "sendudp: send failed");
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

    if ((udp_server_sock = bindtoaddr(udp_server_listen->addrinfo)) < 0)
	debugx(1, DBG_ERR, "udpserverrd: socket/bind failed");

    debug(DBG_WARN, "udpserverrd: listening for UDP on %s:%s",
	  udp_server_listen->host ? udp_server_listen->host : "*", udp_server_listen->port);

    if (pthread_create(&udpserverwrth, NULL, udpserverwr, NULL))
	debugx(1, DBG_ERR, "pthread_create failed");
    
    for (;;) {
	fr = NULL;
	memset(&rq, 0, sizeof(struct request));
	buf = radudpget(udp_server_sock, &fr, NULL, &rq.fromsa);
	to = radsrv(&rq, buf, fr);
	if (!to) {
	    debug(DBG_INFO, "udpserverrd: ignoring request, no place to send it");
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
    
    debug(DBG_DBG, "tlsserverwr starting for %s", client->peer.host);
    replyq = client->replyq;
    pthread_mutex_lock(&replyq->count_mutex);
    for (;;) {
	while (!replyq->count) {
	    if (client->peer.ssl) {	    
		debug(DBG_DBG, "tls server writer, waiting for signal");
		pthread_cond_wait(&replyq->count_cond, &replyq->count_mutex);
		debug(DBG_DBG, "tls server writer, got signal");
	    }
	    if (!client->peer.ssl) {
		/* ssl might have changed while waiting */
		pthread_mutex_unlock(&replyq->count_mutex);
		debug(DBG_DBG, "tlsserverwr: exiting as requested");
		pthread_exit(NULL);
	    }
	}
	pthread_mutex_unlock(&replyq->count_mutex);
	cnt = SSL_write(client->peer.ssl, replyq->replies->buf, RADLEN(replyq->replies->buf));
	if (cnt > 0)
	    debug(DBG_DBG, "tlsserverwr: Sent %d bytes, Radius packet of length %d",
		  cnt, RADLEN(replyq->replies->buf));
	else
	    while ((error = ERR_get_error()))
		debug(DBG_ERR, "tlsserverwr: SSL: %s", ERR_error_string(error, NULL));
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
    SSL *ssl;
    
    debug(DBG_DBG, "tlsserverrd starting for %s", client->peer.host);
    ssl = client->peer.ssl;

    if (SSL_accept(ssl) <= 0) {
        while ((error = ERR_get_error()))
            debug(DBG_ERR, "tlsserverrd: SSL: %s", ERR_error_string(error, NULL));
        debug(DBG_ERR, "SSL_accept failed");
	goto errexit;
    }
    if (tlsverifycert(&client->peer)) {
	if (pthread_create(&tlsserverwrth, NULL, tlsserverwr, (void *)client)) {
	    debug(DBG_ERR, "tlsserverrd: pthread_create failed");
	    goto errexit;
	}
	for (;;) {
	    buf = radtlsget(client->peer.ssl);
	    if (!buf)
		break;
	    debug(DBG_DBG, "tlsserverrd: got Radius message from %s", client->peer.host);
	    memset(&rq, 0, sizeof(struct request));
	    to = radsrv(&rq, buf, client);
	    if (!to) {
		debug(DBG_INFO, "tlsserverrd: ignoring request, no place to send it");
		continue;
	    }
	    sendrq(to, client, &rq);
	}
	debug(DBG_ERR, "tlsserverrd: connection lost");
	/* stop writer by setting peer.ssl to NULL and give signal in case waiting for data */
	client->peer.ssl = NULL;
	pthread_mutex_lock(&client->replyq->count_mutex);
	pthread_cond_signal(&client->replyq->count_cond);
	pthread_mutex_unlock(&client->replyq->count_mutex);
	debug(DBG_DBG, "tlsserverrd: waiting for writer to end");
	pthread_join(tlsserverwrth, NULL);
    }
    
 errexit:
    s = SSL_get_fd(ssl);
    SSL_free(ssl);
    shutdown(s, SHUT_RDWR);
    close(s);
    debug(DBG_DBG, "tlsserverrd thread for %s exiting", client->peer.host);
    client->peer.ssl = NULL;
    pthread_exit(NULL);
}

int tlslistener() {
    pthread_t tlsserverth;
    int s, snew;
    struct sockaddr_storage from;
    size_t fromlen = sizeof(from);
    struct client *client;

    if ((s = bindtoaddr(tcp_server_listen->addrinfo)) < 0)
        debugx(1, DBG_ERR, "tlslistener: socket/bind failed");
    
    listen(s, 0);
    debug(DBG_WARN, "listening for incoming TCP on %s:%s",
	  tcp_server_listen->host ? tcp_server_listen->host : "*", tcp_server_listen->port);

    for (;;) {
	snew = accept(s, (struct sockaddr *)&from, &fromlen);
	if (snew < 0) {
	    debug(DBG_WARN, "accept failed");
	    continue;
	}
	debug(DBG_WARN, "incoming TLS connection from %s", addr2string((struct sockaddr *)&from, fromlen));

	client = find_client('T', (struct sockaddr *)&from, NULL);
	if (!client) {
	    debug(DBG_WARN, "ignoring request, not a known TLS client");
	    shutdown(snew, SHUT_RDWR);
	    close(snew);
	    continue;
	}

	if (client->peer.ssl) {
	    debug(DBG_WARN, "Ignoring incoming TLS connection, already have one from this client");
	    shutdown(snew, SHUT_RDWR);
	    close(snew);
	    continue;
	}
	client->peer.ssl = SSL_new(ssl_ctx);
	SSL_set_fd(client->peer.ssl, snew);
	if (pthread_create(&tlsserverth, NULL, tlsserverrd, (void *)client)) {
	    debug(DBG_ERR, "tlslistener: pthread_create failed");
	    SSL_free(client->peer.ssl);
	    shutdown(snew, SHUT_RDWR);
	    close(snew);
	    client->peer.ssl = NULL;
	    continue;
	}
	pthread_detach(tlsserverth);
    }
    return 0;
}

char *parsehostport(char *s, struct peer *peer) {
    char *p, *field;
    int ipv6 = 0;

    p = s;
    /* allow literal addresses and port, e.g. [2001:db8::1]:1812 */
    if (*p == '[') {
	p++;
	field = p;
	for (; *p && *p != ']' && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	if (*p != ']')
	    debugx(1, DBG_ERR, "no ] matching initial [");
	ipv6 = 1;
    } else {
	field = p;
	for (; *p && *p != ':' && *p != ' ' && *p != '\t' && *p != '\n'; p++);
    }
    if (field == p)
	debugx(1, DBG_ERR, "missing host/address");

    peer->host = stringcopy(field, p - field);
    if (ipv6) {
	p++;
	if (*p && *p != ':' && *p != ' ' && *p != '\t' && *p != '\n')
	    debugx(1, DBG_ERR, "unexpected character after ]");
    }
    if (*p == ':') {
	    /* port number or service name is specified */;
	    field = ++p;
	    for (; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	    if (field == p)
		debugx(1, DBG_ERR, "syntax error, : but no following port");
	    peer->port = stringcopy(field, p - field);
    } else
	peer->port = stringcopy(peer->type == 'U' ? DEFAULT_UDP_PORT : DEFAULT_TLS_PORT, 0);
    return p;
}

/* * is default, else longest match ... ";" used for separator */
char *parserealmlist(char *s, struct server *server) {
    char *p;
    int i, n, l;

    for (p = s, n = 1; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++)
	if (*p == ';')
	    n++;
    l = p - s;
    if (!l)
	debugx(1, DBG_ERR, "realm list must be specified");

    server->realmdata = stringcopy(s, l);
    server->realms = malloc((1+n) * sizeof(char *));
    if (!server->realms)
	debugx(1, DBG_ERR, "malloc failed");
    server->realms[0] = server->realmdata;
    for (n = 1, i = 0; i < l; i++)
	if (server->realmdata[i] == ';') {
	    server->realmdata[i] = '\0';
	    server->realms[n++] = server->realmdata + i + 1;
	}	
    server->realms[n] = NULL;
    return p;
}

FILE *openconfigfile(const char *filename) {
    FILE *f;
    char pathname[100], *base;
    
    f = fopen(filename, "r");
    if (f) {
	debug(DBG_DBG, "reading config file %s", filename);
	return f;
    }

    if (strlen(filename) + 1 <= sizeof(pathname)) {
	/* basename() might modify the string */
	strcpy(pathname, filename);
	base = basename(pathname);
	f = fopen(base, "r");
    }

    if (!f)
	debugx(1, DBG_ERR, "could not read config file %s nor %s\n%s", filename, base, strerror(errno));
    
    debug(DBG_DBG, "reading config file %s", base);
    return f;
}

/* exactly one argument must be non-NULL */
void getconfig(const char *serverfile, const char *clientfile) {
    FILE *f;
    char line[1024];
    char *p, *field, **r;
    struct client *client;
    struct server *server;
    struct peer *peer;
    int i, count, *ucount, *tcount;
 
    f = openconfigfile(serverfile ? serverfile : clientfile);
    if (serverfile) {
	ucount = &server_udp_count;
	tcount = &server_tls_count;
    } else {
	ucount = &client_udp_count;
	tcount = &client_tls_count;
    }
    while (fgets(line, 1024, f)) {
	for (p = line; *p == ' ' || *p == '\t'; p++);
	switch (*p) {
	case '#':
	case '\n':
	    break;
	case 'T':
	    (*tcount)++;
	    break;
	case 'U':
	    (*ucount)++;
	    break;
	default:
	    debugx(1, DBG_ERR, "type must be U or T, got %c", *p);
	}
    }

    if (serverfile) {
	count = server_count = server_udp_count + server_tls_count;
	servers = calloc(count, sizeof(struct server));
	if (!servers)
	    debugx(1, DBG_ERR, "malloc failed");
    } else {
	count = client_count = client_udp_count + client_tls_count;
	clients = calloc(count, sizeof(struct client));
	if (!clients)
	    debugx(1, DBG_ERR, "malloc failed");
    }
    
    if (client_udp_count) {
	udp_server_replyq.replies = malloc(client_udp_count * MAX_REQUESTS * sizeof(struct reply));
	if (!udp_server_replyq.replies)
	    debugx(1, DBG_ERR, "malloc failed");
	udp_server_replyq.size = client_udp_count * MAX_REQUESTS;
	udp_server_replyq.count = 0;
	pthread_mutex_init(&udp_server_replyq.count_mutex, NULL);
	pthread_cond_init(&udp_server_replyq.count_cond, NULL);
    }    
    
    rewind(f);
    for (i = 0; i < count && fgets(line, 1024, f);) {
	if (serverfile) {
	    server = &servers[i];
	    peer = &server->peer;
	} else {
	    client = &clients[i];
	    peer = &client->peer;
	}
	for (p = line; *p == ' ' || *p == '\t'; p++);
	if (*p == '#' || *p == '\n')
	    continue;
	peer->type = *p;	/* we already know it must be U or T */
	for (p++; *p == ' ' || *p == '\t'; p++);
	p = parsehostport(p, peer);
	for (; *p == ' ' || *p == '\t'; p++);
	if (serverfile) {
	    p = parserealmlist(p, server);
	    for (; *p == ' ' || *p == '\t'; p++);
	}
	field = p;
	for (; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	if (field == p) {
	    /* no secret set and end of line, line is complete if TLS */
	    if (peer->type == 'U')
		debugx(1, DBG_ERR, "secret must be specified for UDP");
	    peer->secret = stringcopy(DEFAULT_TLS_SECRET, 0);
	} else {
	    peer->secret = stringcopy(field, p - field);
	    /* check that rest of line only white space */
	    for (; *p == ' ' || *p == '\t'; p++);
	    if (*p && *p != '\n')
		debugx(1, DBG_ERR, "max 4 fields per line, found a 5th");
	}

	if ((serverfile && !resolvepeer(&server->peer, 0)) ||
	    (clientfile && !resolvepeer(&client->peer, 0)))
	    debugx(1, DBG_ERR, "failed to resolve host %s port %s, exiting", peer->host, peer->port);

	if (serverfile) {
	    pthread_mutex_init(&server->lock, NULL);
	    server->sock = -1;
	    server->requests = calloc(MAX_REQUESTS, sizeof(struct request));
	    if (!server->requests)
		debugx(1, DBG_ERR, "malloc failed");
	    server->newrq = 0;
	    pthread_mutex_init(&server->newrq_mutex, NULL);
	    pthread_cond_init(&server->newrq_cond, NULL);
	} else {
	    if (peer->type == 'U')
		client->replyq = &udp_server_replyq;
	    else {
		client->replyq = malloc(sizeof(struct replyq));
		if (!client->replyq)
		    debugx(1, DBG_ERR, "malloc failed");
		client->replyq->replies = calloc(MAX_REQUESTS, sizeof(struct reply));
		if (!client->replyq->replies)
		    debugx(1, DBG_ERR, "malloc failed");
		client->replyq->size = MAX_REQUESTS;
		client->replyq->count = 0;
		pthread_mutex_init(&client->replyq->count_mutex, NULL);
		pthread_cond_init(&client->replyq->count_cond, NULL);
	    }
	}
	debug(DBG_DBG, "got type %c, host %s, port %s, secret %s", peer->type, peer->host, peer->port, peer->secret);
	if (serverfile) {
	    debug(DBG_DBG, "    with realms:");
	    for (r = server->realms; *r; r++)
		debug(DBG_DBG, "\t%s", *r);
	}
	i++;
    }
    fclose(f);
}

struct peer *server_create(char type) {
    struct peer *server;
    char *conf;

    server = malloc(sizeof(struct peer));
    if (!server)
	debugx(1, DBG_ERR, "malloc failed");
    memset(server, 0, sizeof(struct peer));
    server->type = type;
    conf = (type == 'T' ? options.listentcp : options.listenudp);
    if (conf) {
	parsehostport(conf, server);
	if (!strcmp(server->host, "*")) {
	    free(server->host);
	    server->host = NULL;
	}
    } else
	server->port = stringcopy(type == 'T' ? DEFAULT_TLS_PORT : DEFAULT_UDP_PORT, 0);
    if (!resolvepeer(server, AI_PASSIVE))
	debugx(1, DBG_ERR, "failed to resolve host %s port %s, exiting", server->host, server->port);
    return server;
}
		
void getmainconfig(const char *configfile) {
    FILE *f;
    char line[1024];
    char *p, *opt, *endopt, *val, *endval;
    
    f = openconfigfile(configfile);
    memset(&options, 0, sizeof(options));

    while (fgets(line, 1024, f)) {
	for (p = line; *p == ' ' || *p == '\t'; p++);
	if (!*p || *p == '#' || *p == '\n')
	    continue;
	opt = p++;
	for (; *p && *p != ' ' && *p != '\t' && *p != '\n'; p++);
	endopt = p - 1;
	for (; *p == ' ' || *p == '\t'; p++);
	if (!*p || *p == '\n') {
	    endopt[1] = '\0';
	    debugx(1, DBG_ERR, "error in %s, option %s has no value", configfile, opt);
	}
	val = p;
	for (; *p && *p != '\n'; p++)
	    if (*p != ' ' && *p != '\t')
		endval = p;
	endopt[1] = '\0';
	endval[1] = '\0';
	debug(DBG_DBG, "getmainconfig: %s = %s", opt, val);
	
	if (!strcasecmp(opt, "TLSCACertificateFile")) {
	    options.tlscacertificatefile = stringcopy(val, 0);
	    continue;
	}
	if (!strcasecmp(opt, "TLSCACertificatePath")) {
	    options.tlscacertificatepath = stringcopy(val, 0);
	    continue;
	}
	if (!strcasecmp(opt, "TLSCertificateFile")) {
	    options.tlscertificatefile = stringcopy(val, 0);
	    continue;
	}
	if (!strcasecmp(opt, "TLSCertificateKeyFile")) {
	    options.tlscertificatekeyfile = stringcopy(val, 0);
	    continue;
	}
	if (!strcasecmp(opt, "TLSCertificateKeyPassword")) {
	    options.tlscertificatekeypassword = stringcopy(val, 0);
	    continue;
	}
	if (!strcasecmp(opt, "ListenUDP")) {
	    options.listenudp = stringcopy(val, 0);
	    continue;
	}
	if (!strcasecmp(opt, "ListenTCP")) {
	    options.listentcp = stringcopy(val, 0);
	    continue;
	}
	if (!strcasecmp(opt, "StatusServer")) {
	    if (!strcasecmp(val, "on"))
		options.statusserver = 1;
	    else if (strcasecmp(val, "off")) {
		debugx(1, DBG_ERR, "error in %s, value of option %s is %s, must be on or off", configfile, opt, val);
	    }
	    continue;
	}
	if (!strcasecmp(opt, "LogLevel")) {
	    if (strlen(val) != 1 || *val < '1' || *val > '4')
		debugx(1, DBG_ERR, "error in %s, value of option %s is %s, must be 1, 2, 3 or 4", configfile, opt, val);
	    options.loglevel = *val - '0';
	    continue;
	}
	if (!strcasecmp(opt, "LogDestination")) {
	    options.logdestination = stringcopy(val, 0);
	    continue;
	}
	debugx(1, DBG_ERR, "error in %s, unknown option %s", configfile, opt);
    }
    fclose(f);
}

void getargs(int argc, char **argv, uint8_t *foreground, uint8_t *loglevel) {
    int c;

    while ((c = getopt(argc, argv, "d:f")) != -1) {
	switch (c) {
	case 'd':
	    if (strlen(optarg) != 1 || *optarg < '1' || *optarg > '4')
		debugx(1, DBG_ERR, "Debug level must be 1, 2, 3 or 4, not %s", optarg);
	    *loglevel = *optarg - '0';
	    break;
	case 'f':
	    *foreground = 1;
	    break;
	default:
	    goto usage;
	}
    }
    if (!(argc - optind))
	return;

 usage:
    debug(DBG_ERR, "Usage:\n%s [ -f ] [ -d debuglevel ]", argv[0]);
    exit(1);
}

int main(int argc, char **argv) {
    pthread_t udpserverth;
    int i;
    uint8_t foreground = 0, loglevel = 0;
    
    debug_init("radsecproxy");
    debug_set_level(DEBUG_LEVEL);
    getargs(argc, argv, &foreground, &loglevel);
    if (loglevel)
	debug_set_level(loglevel);
    getmainconfig(CONFIG_MAIN);
    if (loglevel)
	options.loglevel = loglevel;
    else if (options.loglevel)
	debug_set_level(options.loglevel);
    if (foreground)
	options.logdestination = NULL;
    else {
	if (!options.logdestination)
	    options.logdestination = "x-syslog://";
	debug_set_destination(options.logdestination);
    }
    getconfig(CONFIG_SERVERS, NULL);
    getconfig(NULL, CONFIG_CLIENTS);

    if (!foreground && (daemon(0, 0) < 0))
	debugx(1, DBG_ERR, "daemon() failed: %s", strerror(errno));
	
    if (client_udp_count) {
	udp_server_listen = server_create('U');
	if (pthread_create(&udpserverth, NULL, udpserverrd, NULL))
	    debugx(1, DBG_ERR, "pthread_create failed");
    }
    
    if (client_tls_count || server_tls_count)
	ssl_ctx = ssl_init();
    
    for (i = 0; i < server_count; i++)
	if (pthread_create(&servers[i].clientth, NULL, clientwr, (void *)&servers[i]))
	    debugx(1, DBG_ERR, "pthread_create failed");

    if (client_tls_count) {
	tcp_server_listen = server_create('T');
	return tlslistener();
    }
    
    /* just hang around doing nothing, anything to do here? */
    for (;;)
	sleep(1000);
}
