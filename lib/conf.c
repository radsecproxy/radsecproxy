/* Copyright 2010, 2011 NORDUnet A/S. All rights reserved.
   See the file COPYING for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <confuse.h>
#include <string.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>
#include "peer.h"
#include "debug.h"

#if 0
  # common config options
  dictionary = STRING

  # common realm config options
  realm NAME {
      type = "UDP"|"TCP"|"TLS"|"DTLS"
      timeout = INT
      retries = INT
      cacertfile = STRING
      #cacertpath = STRING
      certfile = STRING
      certkeyfile = STRING
  }

  # client specific realm config options
  realm NAME {
      server {
          hostname = STRING
	  service = STRING
	  secret = STRING
      }
  }
#endif

int
rs_context_read_config(struct rs_context *ctx, const char *config_file)
{
  /* FIXME: Missing some error handling!  */

  cfg_t *cfg, *cfg_realm, *cfg_server;
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
      CFG_SEC ("server", server_opts, CFGF_MULTI),
      CFG_END ()
    };
  cfg_opt_t opts[] =
    {
      CFG_STR ("dictionary", NULL, CFGF_NONE),
      CFG_SEC ("realm", realm_opts, CFGF_TITLE | CFGF_MULTI),
      CFG_END ()
    };

  cfg = cfg_init (opts, CFGF_NONE);
  if (cfg_parse (cfg, config_file) == CFG_PARSE_ERROR)
    return rs_err_ctx_push (ctx, RSE_CONFIG, "%s: invalid configuration file",
			    config_file);

  config = rs_calloc (ctx, 1, sizeof (*config));
  if (config == NULL)
    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);
  ctx->config = config;
  config->dictionary = cfg_getstr (cfg, "dictionary");

  for (i = 0; i < cfg_size (cfg, "realm"); i++)
    {
      struct rs_realm *r = rs_calloc (ctx, 1, sizeof(*r));
      const char *typestr;

      if (!r)
	return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);
      if (config->realms)
	{
	  r->next = config->realms->next;
	  config->realms->next = r;
	}
      else
	  config->realms = r;
      cfg_realm = cfg_getnsec (cfg, "realm", i);
      s = cfg_title (cfg_realm);
      if (s == NULL)
	return rs_err_ctx_push_fl (ctx, RSE_CONFIG, __FILE__, __LINE__,
				   "missing config name");
      r->name = strdup (s);	/* FIXME: Don't strdup.  */
      if (!r->name)
	return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);

      typestr = cfg_getstr (cfg_realm, "type");
      if (!strcmp (typestr, "UDP"))
	r->type = RS_CONN_TYPE_UDP;
      else if (!strcmp (typestr, "TCP"))
	r->type = RS_CONN_TYPE_TCP;
      else if (!strcmp (typestr, "TLS"))
	r->type = RS_CONN_TYPE_TLS;
      else if (!strcmp (typestr, "DTLS"))
	r->type = RS_CONN_TYPE_DTLS;
      else
	return rs_err_ctx_push_fl (ctx, RSE_CONFIG, __FILE__, __LINE__,
				   "invalid connection type: %s", typestr);
      r->timeout = cfg_getint (cfg_realm, "timeout");
      r->retries = cfg_getint (cfg_realm, "retries");

      r->cacertfile = cfg_getstr (cfg_realm, "cacertfile");
      /*r->cacertpath = cfg_getstr (cfg_realm, "cacertpath");*/
      r->certfile = cfg_getstr (cfg_realm, "certfile");
      r->certkeyfile = cfg_getstr (cfg_realm, "certkeyfile");

      /* Add peers, one per server stanza.  */
      for (j = 0; j < cfg_size (cfg_realm, "server"); j++)
	{
	  struct rs_peer *p = peer_create (ctx, &r->peers);
	  if (!p)
	    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__,
				       NULL);
	  p->realm = r;

	  cfg_server = cfg_getnsec (cfg_realm, "server", j);
	  rs_resolv (&p->addr, r->type, cfg_getstr (cfg_server, "hostname"),
		     cfg_getstr (cfg_server, "service"));
	  p->secret = cfg_getstr (cfg_server, "secret");
	}
    }

  /* Save config object in context, for freeing in
     rs_context_destroy().  */
  ctx->config->cfg =  cfg;
  return RSE_OK;
}

struct rs_realm *
rs_conf_find_realm(struct rs_context *ctx, const char *name)
{
  struct rs_realm *r;

  for (r = ctx->config->realms; r; r = r->next)
    if (!strcmp (r->name, name))
	return r;
  return NULL;
}
