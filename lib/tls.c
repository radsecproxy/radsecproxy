/* Copyright 2010-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

#include <regex.h>
#include "radsecproxy/list.h"
#include "radsecproxy/radsecproxy.h"

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

int
rs_tls_init (struct rs_connection *conn)
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

  if (!success)
    err = rs_err_conn_push (conn, RSE_CERT, "server certificate doesn't "
                            "match configured hostname \"%s\"", hostname);

 out:
  if (peer_cert != NULL)
    X509_free (peer_cert);
  return err;
}
