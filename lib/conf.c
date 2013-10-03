/* Copyright 2010-2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information. */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <confuse.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "peer.h"
#include "util.h"
#include "debug.h"

#if 0
  # common config options

  # common realm config options
  realm STRING {
      type = "UDP"|"TCP"|"TLS"|"DTLS"
      timeout = INT
      retries = INT
      cacertfile = STRING
      #cacertpath = STRING
      certfile = STRING
      certkeyfile = STRING
      pskstr = STRING	# Transport pre-shared key, UTF-8 form.
      pskhexstr = STRING # Transport pre-shared key, ASCII hex form.
      pskid = STRING
      pskex = "PSK"|"DHE_PSK"|"RSA_PSK"
      disable_hostname_check = "yes"|"no"
  }

  # client specific realm config options
  realm STRING {
      server {
          hostname = STRING
	  service = STRING
          secret = STRING       # RADIUS secret
      }
  }
#endif

/* FIXME: Leaking memory in error cases.  */
int
rs_context_read_config(struct rs_context *ctx, const char *config_file)
{
  cfg_t *cfg, *cfg_realm, *cfg_server;
  int err = 0;
  int i, j;
  const char *s;
  struct rs_config *config = NULL;

  cfg_opt_t server_opts[] =
    {
      CFG_STR ("hostname", NULL, CFGF_NONE),
      CFG_STR ("service", "2083", CFGF_NONE),
      CFG_STR ("secret", "radsec", CFGF_NONE),
      CFG_END ()
    };
  cfg_opt_t realm_opts[] =
    {
      CFG_STR ("type", "UDP", CFGF_NONE),
      CFG_INT ("timeout", 2, CFGF_NONE), /* FIXME: Remove?  */
      CFG_INT ("retries", 2, CFGF_NONE), /* FIXME: Remove?  */
      CFG_STR ("cacertfile", NULL, CFGF_NONE),
      /*CFG_STR ("cacertpath", NULL, CFGF_NONE),*/
      CFG_STR ("certfile", NULL, CFGF_NONE),
      CFG_STR ("certkeyfile", NULL, CFGF_NONE),
      CFG_STR ("pskstr", NULL, CFGF_NONE),
      CFG_STR ("pskhexstr", NULL, CFGF_NONE),
      CFG_STR ("pskid", NULL, CFGF_NONE),
      CFG_STR ("pskex", "PSK", CFGF_NONE),
      CFG_BOOL ("disable_hostname_check", cfg_false, CFGF_NONE),
      CFG_SEC ("server", server_opts, CFGF_MULTI),
      CFG_END ()
    };
  cfg_opt_t opts[] =
    {
      CFG_SEC ("realm", realm_opts, CFGF_TITLE | CFGF_MULTI),
      CFG_END ()
    };

  cfg = cfg_init (opts, CFGF_NONE);
  if (cfg == NULL)
    return rs_err_ctx_push (ctx, RSE_CONFIG, "unable to initialize libconfuse");
  err = cfg_parse (cfg, config_file);
  switch (err)
    {
    case  CFG_SUCCESS:
      break;
    case CFG_FILE_ERROR:
      return rs_err_ctx_push (ctx, RSE_CONFIG,
			      "%s: unable to open configuration file",
			      config_file);
    case CFG_PARSE_ERROR:
      return rs_err_ctx_push (ctx, RSE_CONFIG, "%s: invalid configuration file",
			      config_file);
    default:
	return rs_err_ctx_push (ctx, RSE_CONFIG, "%s: unknown parse error",
				config_file);
    }

  config = rs_calloc (ctx, 1, sizeof (*config));
  if (config == NULL)
    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);
  ctx->config = config;

  for (i = 0; i < cfg_size (cfg, "realm"); i++)
    {
      struct rs_realm *r = NULL;
      const char *typestr;
      char *pskstr = NULL, *pskhexstr = NULL;

      r = rs_calloc (ctx, 1, sizeof(*r));
      if (r == NULL)
	return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);
      if (config->realms != NULL)
	{
	  r->next = config->realms->next;
	  config->realms->next = r;
	}
      else
	{
	  config->realms = r;
	}
      cfg_realm = cfg_getnsec (cfg, "realm", i);
      s = cfg_title (cfg_realm);
      if (s == NULL)
	return rs_err_ctx_push_fl (ctx, RSE_CONFIG, __FILE__, __LINE__,
				   "missing realm name");
      /* We use a copy of the return value of cfg_title() since it's const.  */
      r->name = rs_strdup (ctx, s);
      if (r->name == NULL)
	return RSE_NOMEM;

      typestr = cfg_getstr (cfg_realm, "type");
      if (strcmp (typestr, "UDP") == 0)
	r->type = RS_CONN_TYPE_UDP;
      else if (strcmp (typestr, "TCP") == 0)
	r->type = RS_CONN_TYPE_TCP;
      else if (strcmp (typestr, "TLS") == 0)
	r->type = RS_CONN_TYPE_TLS;
      else if (strcmp (typestr, "DTLS") == 0)
	r->type = RS_CONN_TYPE_DTLS;
      else
	return rs_err_ctx_push (ctx, RSE_CONFIG,
                                "%s: invalid connection type: %s",
                                r->name, typestr);
      r->timeout = cfg_getint (cfg_realm, "timeout");
      r->retries = cfg_getint (cfg_realm, "retries");
      r->disable_hostname_check = cfg_getbool (cfg_realm, "disable_hostname_check");

      r->cacertfile = cfg_getstr (cfg_realm, "cacertfile");
      /*r->cacertpath = cfg_getstr (cfg_realm, "cacertpath");*/
      r->certfile = cfg_getstr (cfg_realm, "certfile");
      r->certkeyfile = cfg_getstr (cfg_realm, "certkeyfile");

      pskstr = cfg_getstr (cfg_realm, "pskstr");
      pskhexstr = cfg_getstr (cfg_realm, "pskhexstr");
      if (pskstr || pskhexstr)
        {
#if defined RS_ENABLE_TLS_PSK
          char *kex = cfg_getstr (cfg_realm, "pskex");
          rs_cred_type_t type = RS_CRED_NONE;
          struct rs_credentials *cred = NULL;
          assert (kex != NULL);

          if (!strcmp (kex, "PSK"))
            type = RS_CRED_TLS_PSK;
          else
            {
              /* TODO: push a warning on the error stack:*/
              /*rs_err_ctx_push (ctx, RSE_WARN, "%s: unsupported PSK key exchange"
                               " algorithm -- PSK not used", kex);*/
            }

          if (type != RS_CRED_NONE)
            {
              cred = rs_calloc (ctx, 1, sizeof (*cred));
              if (cred == NULL)
                return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__,
                                           NULL);
              cred->type = type;
              cred->identity = cfg_getstr (cfg_realm, "pskid");
              if (pskhexstr)
                {
                  cred->secret_encoding = RS_KEY_ENCODING_ASCII_HEX;
                  cred->secret = pskhexstr;
                  if (pskstr)
                    ;      /* TODO: warn that we're ignoring pskstr */
                }
              else
                {
                  cred->secret_encoding = RS_KEY_ENCODING_UTF8;
                  cred->secret = pskstr;
                }

              r->transport_cred = cred;
            }
#else  /* !RS_ENABLE_TLS_PSK */
          /* TODO: push a warning on the error stack: */
          /* rs_err_ctx_push (ctx, RSE_WARN, "libradsec wasn't configured with "
                           "support for TLS preshared keys, ignoring pskstr "
                           "and pskhexstr");*/
#endif  /* RS_ENABLE_TLS_PSK */
        }

      /* For TLS and DTLS realms, validate that we either have (i) CA
         cert file or path or (ii) PSK.  */
      if ((r->type == RS_CONN_TYPE_TLS || r->type == RS_CONN_TYPE_DTLS)
          && (r->cacertfile == NULL && r->cacertpath == NULL)
          && r->transport_cred == NULL)
        return rs_err_ctx_push (ctx, RSE_CONFIG,
                                "%s: missing both CA file/path and PSK",
                                r->name);

      /* Add peers, one per server stanza.  */
      for (j = 0; j < cfg_size (cfg_realm, "server"); j++)
	{
	  struct rs_peer *p = peer_create (ctx, &r->peers);
	  if (p == NULL)
	    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__,
				       NULL);
	  p->realm = r;

	  cfg_server = cfg_getnsec (cfg_realm, "server", j);
	  p->hostname = cfg_getstr (cfg_server, "hostname");
          p->service = cfg_getstr (cfg_server, "service");
	  p->secret = cfg_getstr (cfg_server, "secret");
	}
    }

  /* Save config object in context, for freeing in rs_context_destroy().  */
  ctx->config->cfg = cfg;

  return RSE_OK;
}

struct rs_realm *
rs_conf_find_realm(struct rs_context *ctx, const char *name)
{
  struct rs_realm *r;
  assert (ctx);

  if (ctx->config)
    for (r = ctx->config->realms; r; r = r->next)
      if (strcmp (r->name, name) == 0)
	return r;

  return NULL;
}
