/* Copyright 2010, 2011, 2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

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

#if 0 /* Configuration file syntax. */
  # realm specific configuration
  realm STRING {
      type = "UDP"|"TCP"|"TLS"|"DTLS"
      timeout = INT
      retries = INT
  }

  # realm configuration inherited by clients and servers
  realm STRING {
      cacertfile = STRING
      #cacertpath = STRING
      certfile = STRING
      certkeyfile = STRING
      pskstr = STRING	 # Transport pre-shared key, UTF-8 form.
      pskhexstr = STRING # Transport pre-shared key, ASCII hex form.
      pskid = STRING
      pskex = "PSK"|"DHE_PSK"|"RSA_PSK"
  }

  # client configuration
  realm STRING {
      server {
          hostname = STRING
	  service = STRING      # name or port number
          secret = STRING       # RADIUS secret
      }
  }

  # server configuration
  realm STRING {
      client {
          hostname = STRING
	  service = STRING      # name or port number
          secret = STRING       # RADIUS secret
      }
  }
#endif

struct confcommon {
  struct rs_credentials *transport_cred;
  char *cacertfile;
  char *cacertpath;
  char *certfile;
  char *certkeyfile;
  char *pskstr;
  char *pskhexstr;
};

#define CONFGET_STR(dst,cfg,key,def) do {  \
        (dst) = cfg_getstr ((cfg), (key)); \
        if ((dst) == NULL) (dst) = (def);  \
      } while (0)
#define CONFGET_INT(dst,cfg,key,def) do {  \
        (dst) = cfg_getint ((cfg), (key)); \
        if ((dst) == -1) (dst) = (def);    \
      } while (0)

static int
confload_peers (struct rs_context *ctx,
                /*const*/ cfg_t *cfg_realm,
                enum rs_peer_type type,
                struct rs_realm *r)
{
  const char *peer_type_str[] = {"<no type>", "client", "server"};
  cfg_t *cfg_peer = NULL;
  int j;
  char *def_cacertfile = cfg_getstr (cfg_realm, "cacertfile");
  /*char *def_cacertpath = cfg_getstr (cfg_realm, "cacertpath");*/
  char *def_certfile = cfg_getstr (cfg_realm, "certfile");
  char *def_certkeyfile = cfg_getstr (cfg_realm, "certkeyfile");
  char *def_pskstr = cfg_getstr (cfg_realm, "pskstr");
  char *def_pskhexstr = cfg_getstr (cfg_realm, "pskhexstr");

  for (j = 0; j < cfg_size (cfg_realm, peer_type_str[type]); j++)
    {
      char *pskstr = NULL;
      char *pskhexstr = NULL;
      struct rs_peer *p = peer_create (ctx, &r->peers);
      if (p == NULL)
        return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__,
                                   NULL);
      p->type = type;
      p->realm = r;

      cfg_peer = cfg_getnsec (cfg_realm, peer_type_str[type], j);
      p->hostname = cfg_getstr (cfg_peer, "hostname");
      p->service = cfg_getstr (cfg_peer, "service");
      p->secret = cfg_getstr (cfg_peer, "secret");

      CONFGET_STR (p->cacertfile, cfg_peer, "cacertfile", def_cacertfile);
      CONFGET_STR (p->certfile, cfg_peer, "certfile", def_certfile);
      CONFGET_STR (p->certkeyfile, cfg_peer, "certkeyfile", def_certkeyfile);
      CONFGET_STR (pskstr, cfg_peer, "pskstr", def_pskstr);
      CONFGET_STR (pskhexstr, cfg_peer, "pskhexstr", def_pskhexstr);

      if (pskstr || pskhexstr)
        {
#if defined RS_ENABLE_TLS_PSK
          char *def_pskex = cfg_getstr (cfg_realm, "pskex");
          char *tmp_pskex = NULL;
          rs_cred_type_t type = RS_CRED_NONE;
          struct rs_credentials *cred = NULL;

          CONFGET_STR (tmp_pskex, cfg_peer, "pskex", def_pskex);
          if (!strcmp (tmp_pskex, "PSK"))
            type = RS_CRED_TLS_PSK;
          else
            {
              /* TODO: push a warning on the error stack:*/
              /*rs_err_ctx_push (ctx, RSE_WARN, "%s: unsupported PSK key exchange"
                               " algorithm -- PSK not used", kex);*/
            }

          if (type != RS_CRED_NONE)
            {
              char *def_pskid = cfg_getstr (cfg_realm, "pskid");
              cred = rs_calloc (ctx, 1, sizeof (*cred));
              if (cred == NULL)
                return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__,
                                           NULL);
              cred->type = type;
              CONFGET_STR (cred->identity, cfg_peer, "pskid", def_pskid);
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

              p->transport_cred = cred;
            }
#else  /* !RS_ENABLE_TLS_PSK */
          /* TODO: push a warning on the error stack: */
          /* rs_err_ctx_push (ctx, RSE_WARN, "libradsec wasn't configured with "
             "support for TLS preshared keys, ignoring pskstr "
             "and pskhexstr");*/
#endif  /* RS_ENABLE_TLS_PSK */
        }


      /* For a TLS or DTLS client or server, validate that we have either of CA
         cert file/path or PSK.  */
      if ((r->type == RS_CONN_TYPE_TLS || r->type == RS_CONN_TYPE_DTLS)
          && (p->cacertfile == NULL && p->cacertpath == NULL)
          && p->transport_cred == NULL)
        return rs_err_ctx_push (ctx, RSE_CONFIG,
                                "%s: missing both CA file/path and PSK",
                                r->name);
    }

  return RSE_OK;
}

/* FIXME: Leaking memory in error cases.  */
int
rs_context_read_config(struct rs_context *ctx, const char *config_file)
{
  cfg_t *cfg, *cfg_realm;
  int err = 0;
  int i;
  const char *s;
  struct rs_config *config = NULL;

  cfg_opt_t peer_opts[] =
    {
      CFG_STR ("hostname", NULL, CFGF_NONE),
      CFG_STR ("service", "2083", CFGF_NONE),
      CFG_STR ("secret", "radsec", CFGF_NONE),
      CFG_STR ("cacertfile", NULL, CFGF_NONE),
      /*CFG_STR ("cacertpath", NULL, CFGF_NONE),*/
      CFG_STR ("certfile", NULL, CFGF_NONE),
      CFG_STR ("certkeyfile", NULL, CFGF_NONE),
      CFG_STR ("pskstr", NULL, CFGF_NONE),
      CFG_STR ("pskhexstr", NULL, CFGF_NONE),
      CFG_STR ("pskid", NULL, CFGF_NONE),
      CFG_STR ("pskex", "PSK", CFGF_NONE),

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
      CFG_SEC ("server", peer_opts, CFGF_MULTI),
      CFG_SEC ("client", peer_opts, CFGF_MULTI),
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
      struct confcommon cc;

      memset (&cc, 0, sizeof(cc));
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

      /* Add client and server peers. */
      err = confload_peers (ctx, cfg_realm, RS_PEER_TYPE_CLIENT, r);
      if (err)
        return err;
      err = confload_peers (ctx, cfg_realm, RS_PEER_TYPE_SERVER, r);
      if (err)
        return err;
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
