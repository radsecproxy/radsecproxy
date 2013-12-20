/* Copyright 2010-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#if defined HAVE_PTHREAD_H
#include <pthread.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

#include <regex.h>
#include "radsecproxy/list.h"
#include "radsecproxy/radsecproxy.h"

#include "tls.h"

static struct tls *
_get_tlsconf (struct rs_connection *conn, const struct rs_realm *realm)
{
  struct tls *c = rs_malloc (conn->ctx, sizeof (struct tls));

  if (c)
    {
      memset (c, 0, sizeof (struct tls));
      /* TODO: Make sure old radsecproxy code doesn't free these all
	 of a sudden, or strdup them.  */
      c->name = realm->name;
      c->cacertfile = realm->cacertfile;
      c->cacertpath = NULL;	/* NYI */
      c->certfile = realm->certfile;
      c->certkeyfile = realm->certkeyfile;
      c->certkeypwd = NULL;	/* NYI */
      c->cacheexpiry = 0;	/* NYI */
      c->crlcheck = 0;		/* NYI */
      c->policyoids = (char **) NULL; /* NYI */
    }
    else
      rs_err_conn_push_fl (conn, RSE_NOMEM, __FILE__, __LINE__, NULL);

  return c;
}

#if defined RS_ENABLE_TLS_PSK
static unsigned int
psk_client_cb (SSL *ssl,
               const char *hint,
               char *identity,
               unsigned int max_identity_len,
               unsigned char *psk,
               unsigned int max_psk_len)
{
  struct rs_connection *conn = NULL;
  struct rs_credentials *cred = NULL;

  conn = SSL_get_ex_data (ssl, 0);
  assert (conn != NULL);
  cred = conn->active_peer->realm->transport_cred;
  assert (cred != NULL);
  /* NOTE: Ignoring identity hint from server.  */

  if (strlen (cred->identity) + 1 > max_identity_len)
    {
      rs_err_conn_push (conn, RSE_CRED, "PSK identity longer than max %d",
                        max_identity_len - 1);
      return 0;
    }
  strcpy (identity, cred->identity);

  switch (cred->secret_encoding)
    {
    case RS_KEY_ENCODING_UTF8:
      cred->secret_len = strlen (cred->secret);
      if (cred->secret_len > max_psk_len)
        {
          rs_err_conn_push (conn, RSE_CRED, "PSK secret longer than max %d",
                            max_psk_len);
          return 0;
        }
      memcpy (psk, cred->secret, cred->secret_len);
      break;
    case RS_KEY_ENCODING_ASCII_HEX:
      {
        BIGNUM *bn = NULL;

        if (BN_hex2bn (&bn, cred->secret) == 0)
          {
            rs_err_conn_push (conn, RSE_CRED, "Unable to convert pskhexstr");
            if (bn != NULL)
              BN_clear_free (bn);
            return 0;
          }
        if ((unsigned int) BN_num_bytes (bn) > max_psk_len)
          {
            rs_err_conn_push (conn, RSE_CRED, "PSK secret longer than max %d",
                             max_psk_len);
            BN_clear_free (bn);
            return 0;
          }
        cred->secret_len = BN_bn2bin (bn, psk);
        BN_clear_free (bn);
      }
      break;
    default:
      assert (!"unknown psk encoding");
    }

  return cred->secret_len;
}
#endif  /* RS_ENABLE_TLS_PSK */

/** Read \a buf_len bytes from one of the random devices into \a
    buf. Return 0 on success and -1 on failure. */
static int
load_rand_ (uint8_t *buf, size_t buf_len)
{
  static const char *fns[] = {"/dev/urandom", "/dev/random", NULL};
  int i;

  if (buf_len > SSIZE_MAX)
    return -1;

  for (i = 0; fns[i] != NULL; i++)
    {
      size_t nread = 0;
      int fd = open (fns[i], O_RDONLY);
      if (fd < 0)
        continue;
      while (nread != buf_len)
        {
          ssize_t r = read (fd, buf + nread, buf_len - nread);
          if (r < 0)
            return -1;
          if (r == 0)
            break;
          nread += r;
        }
      close (fd);
      if (nread != buf_len)
        return -1;
      return 0;
    }
  return -1;
}

/** Initialise OpenSSL's PRNG by possibly invoking RAND_poll() and by
    feeding RAND_seed() data from one of the random devices. If either
    succeeds, we're happy and return 0. */
static int
init_openssl_rand_ (void)
{
  long openssl_version = 0;
  int openssl_random_init_flag = 0;
  int our_random_init_flag = 0;
  uint8_t buf[32];

  /* Older OpenSSL has a crash bug in RAND_poll (when a file it opens
     gets a file descriptor with a number higher than FD_SETSIZE) so
     use it only for newer versions. */
  openssl_version = SSLeay ();
  if (openssl_version >= OPENSSL_V (0,9,8,'c'))
    openssl_random_init_flag = RAND_poll ();

  our_random_init_flag = !load_rand_ (buf, sizeof(buf));
  if (our_random_init_flag)
    RAND_seed (buf, sizeof(buf));
  memset (buf, 0, sizeof(buf)); /* FIXME: What if memset() is optimised out? */

  if (!openssl_random_init_flag && !our_random_init_flag)
    return -1;
  if (!RAND_bytes (buf, sizeof(buf)))
    return -1;
  return 0;
}

#if defined HAVE_PTHREADS
/** Array of pthread_mutex_t for OpenSSL. Allocated and initialised in
    \a init_locking_ and never freed. */
static pthread_mutex_t *s_openssl_mutexes = NULL;
/** Number of pthread_mutex_t's allocated at s_openssl_mutexes. */
static int s_openssl_mutexes_count = 0;

/** Callback for OpenSSL when a lock is to be held or released. */
static void
openssl_locking_cb_ (int mode, int i, const char *file, int line)
{
  if (s_openssl_mutexes == NULL || i >= s_openssl_mutexes_count)
    return;
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock (&s_openssl_mutexes[i]);
  else
    pthread_mutex_unlock (&s_openssl_mutexes[i]);
}

/** Initialise any locking needed for being thread safe. Libradsec has
    all its own state in one or more struct rs_context and doesn't
    need locks but libraries used by libradsec may need protection. */
static int
init_locking_ ()
{
  int i, n;
  n = CRYPTO_num_locks ();

  s_openssl_mutexes = calloc (n, sizeof(pthread_mutex_t));
  if (s_openssl_mutexes == NULL)
    return -RSE_NOMEM;
  for (i = 0; i < n; i++)
    pthread_mutex_init (&s_openssl_mutexes[i], NULL);
  s_openssl_mutexes_count = n;

  return 0;
}
#endif  /* HAVE_PTHREADS */

/** Initialise the TLS library. Return 0 on success, -1 on failure. */
int
tls_init ()
{
  SSL_load_error_strings ();
#if defined HAVE_PTHREADS
  if (CRYPTO_get_locking_callback () == NULL)
    {
      assert (s_openssl_mutexes_count == 0);
      /* Allocate and initialise mutexes. We will never free
         these. FIXME: Is there a portable way of having a function
         invoked when a solib is unloaded? -ln */
      if (init_locking_ ())
        return -1;
      CRYPTO_set_locking_callback (openssl_locking_cb_);
    }
#endif  /* HAVE_PTHREADS */
  SSL_library_init ();
  return init_openssl_rand_ ();
}

int
tls_init_conn (struct rs_connection *conn)
{
  struct rs_context *ctx = NULL;
  struct tls *tlsconf = NULL;
  SSL_CTX *ssl_ctx = NULL;
  SSL *ssl = NULL;
  unsigned long sslerr = 0;

  assert (conn->ctx);
  ctx = conn->ctx;

  tlsconf = _get_tlsconf (conn, conn->active_peer->realm);
  if (!tlsconf)
    return -1;
  ssl_ctx = tlsgetctx (RAD_TLS, tlsconf);
  if (!ssl_ctx)
    {
      for (sslerr = ERR_get_error (); sslerr; sslerr = ERR_get_error ())
	 rs_err_conn_push_fl (conn, RSE_SSLERR, __FILE__, __LINE__,
			      ERR_error_string (sslerr, NULL));
      return -1;
    }
  ssl = SSL_new (ssl_ctx);
  if (!ssl)
    {
      for (sslerr = ERR_get_error (); sslerr; sslerr = ERR_get_error ())
	rs_err_conn_push_fl (conn, RSE_SSLERR, __FILE__, __LINE__,
			     ERR_error_string (sslerr, NULL));
      return -1;
    }

#if defined RS_ENABLE_TLS_PSK
  if (conn->active_peer->realm->transport_cred != NULL)
    {
      SSL_set_psk_client_callback (ssl, psk_client_cb);
      SSL_set_ex_data (ssl, 0, conn);
    }
#endif  /* RS_ENABLE_TLS_PSK */

  conn->tls_ctx = ssl_ctx;
  conn->tls_ssl = ssl;
  rs_free (ctx, tlsconf);
  return RSE_OK;
}

/* draft-ietf-radext-radsec-11.txt

       *  Certificate validation MUST include the verification rules as
          per [RFC5280].

       *  Implementations SHOULD indicate their acceptable Certification
          Authorities as per section 7.4.4 (server side) and x.y.z
          ["Trusted CA Indication"] (client side) of [RFC5246] (see
          Section 3.2)

       *  Implementations SHOULD allow to configure a list of acceptable
          certificates, identified via certificate fingerprint.  When a
          fingerprint configured, the fingerprint is prepended with an
          ASCII label identifying the hash function followed by a colon.
          Implementations MUST support SHA-1 as the hash algorithm and
          use the ASCII label "sha-1" to identify the SHA-1 algorithm.
          The length of a SHA-1 hash is 20 bytes and the length of the
          corresponding fingerprint string is 65 characters.  An example
          certificate fingerprint is: sha-
          1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D

       *  Peer validation always includes a check on whether the locally
          configured expected DNS name or IP address of the server that
          is contacted matches its presented certificate.  DNS names and
          IP addresses can be contained in the Common Name (CN) or
          subjectAltName entries.  For verification, only one of these
          entries is to be considered.  The following precedence
          applies: for DNS name validation, subjectAltName:DNS has
          precedence over CN; for IP address validation, subjectAltName:
          iPAddr has precedence over CN.

       *  Implementations SHOULD allow to configure a set of acceptable
          values for subjectAltName:URI.
 */
int
tls_verify_cert (struct rs_connection *conn)
{
  int err = 0;
  int success = 0;
  X509 *peer_cert = NULL;
  struct in6_addr addr;
  const char *hostname = NULL;

  assert (conn->active_peer->conn == conn);
  assert (conn->active_peer->hostname != NULL);
  hostname = conn->active_peer->hostname;

  /* verifytlscert() performs basic verification as described by
     OpenSSL VERIFY(1), i.e. verification of the certificate chain.  */
  peer_cert = verifytlscert (conn->tls_ssl);
  if (peer_cert == NULL)
    {
      err = rs_err_conn_push (conn, RSE_SSLERR,
                              "basic certificate validation failed");
      goto out;
    }

  if (inet_pton (AF_INET, hostname, &addr))
    success = (subjectaltnameaddr (peer_cert, AF_INET, &addr) == 1);
  else if (inet_pton (AF_INET6, hostname, &addr))
    success = (subjectaltnameaddr (peer_cert, AF_INET6, &addr) == 1);
  else
    success = (subjectaltnameregexp (peer_cert, GEN_DNS, hostname, NULL) == 1);

  if (!success)
    success = (cnregexp (peer_cert, hostname, NULL) == 1);

  if (conn->realm->disable_hostname_check)
    success = 1;
  if (!success)
    err = rs_err_conn_push (conn, RSE_CERT, "server certificate doesn't "
                            "match configured hostname \"%s\"", hostname);

 out:
  if (peer_cert != NULL)
    X509_free (peer_cert);
  return err;
}
