#include <confuse.h>
#include <string.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

#if 0
  # example of client config
  config NAME {
      type = "UDP|TCP|TLS|DTLS"
      server {
          hostname = STRING
	  service = STRING
	  secret = STRING
	  timeout = INT         /* optional */
	  tries = INT		/* optional */
      }
  }
#endif

int
rs_context_read_config(struct rs_context *ctx, const char *config_file)
{
#warning "Missing some error handling in rs_context_config_read()"
  cfg_opt_t server_opts[] =
    {
      CFG_STR ("hostname", NULL, CFGF_NONE),
      CFG_STR ("service", "radius", CFGF_NONE),
      CFG_STR ("secret", NULL, CFGF_NONE),
      CFG_INT ("timeout", 3, CFGF_NONE),
      CFG_INT ("tries", 1, CFGF_NONE),
      CFG_END ()
    };
  cfg_opt_t config_opts[] =
    {
      CFG_STR ("type", "UDP", CFGF_NONE),
      CFG_SEC ("server", server_opts, CFGF_MULTI),
      CFG_END ()
    };
  cfg_opt_t opts[] =
    {
      CFG_SEC ("config", config_opts, CFGF_TITLE | CFGF_MULTI),
      CFG_END ()
    };
  cfg_t *cfg, *cfg_config, *cfg_server;
  int i, j;

  cfg = cfg_init (opts, CFGF_NONE);
  if (cfg_parse (cfg, config_file) == CFG_PARSE_ERROR)
    return rs_err_ctx_push (ctx, RSE_CONFIG, "%s: invalid configuration file",
			    config_file);
  for (i = 0; i < cfg_size (cfg, "config"); i++)
    {
      struct rs_realm *r = rs_malloc (ctx, sizeof(*r));
      const char *typestr;

      if (!r)
	return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__, NULL);
      memset (r, 0, sizeof(*r));
      if (ctx->realms)
	ctx->realms->next = r;
      else
	ctx->realms = r;
      cfg_config = cfg_getnsec (cfg, "config", i);
      r->name = strdup (cfg_title (cfg_config));
      typestr = cfg_getstr (cfg_config, "type");
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
				   "%s: invalid connection type", typestr);

      /* Add peers, one per server stanza.  */
      for (j = 0; j < cfg_size (cfg_config, "server"); j++)
	{
	  struct rs_peer *p = _rs_peer_create (ctx, &r->peers);
	  if (!p)
	    return rs_err_ctx_push_fl (ctx, RSE_NOMEM, __FILE__, __LINE__,
				       NULL);

	  cfg_server = cfg_getnsec (cfg_config, "server", j);
	  _rs_resolv (&p->addr, r->type, cfg_getstr (cfg_server, "hostname"),
		      cfg_getstr (cfg_server, "service"));
	  p->secret = strdup (cfg_getstr (cfg_server, "secret"));
	  p->timeout = cfg_getint (cfg_server, "timeout");
	  p->tries = cfg_getint (cfg_server, "tries");
	}
    }
  return RSE_OK;
}

struct rs_realm
*rs_conf_find_realm(struct rs_context *ctx, const char *name)
{
  struct rs_realm *r;

  for (r = ctx->realms; r; r = r->next)
    if (!strcmp (r->name, name))
	return r;
  return NULL;
}
