/* Copyright 2013 NORDUnet A/S. All rights reserved.
   See LICENSE for licensing information.  */

#if defined HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <radsec/radsec.h>
#include <radsec/radsec-impl.h>

#if 0
/* This code triggers the memory-stomping-detector of electric fence */

#define MEMCHUNK 30

static int
print_to_buf (const struct rs_context *ctx,
              char **buf_ptr, ssize_t *i_ptr, ssize_t *len_ptr,
              const char *fmt, ...)
{
  char *buf = *buf_ptr;
  ssize_t i = *i_ptr;
  ssize_t len = *len_ptr;

  va_list args;
  for (;;)
    {
      int n;
      va_start (args, fmt);
      fprintf (stdout, "sprintf (%p + %ld, %ld, \"%s\") -->",
               buf, i, len, buf);
      fflush (stdout);
      n = vsnprintf (buf + i, len - i, fmt, args);
      fprintf (stdout, "%d\n", n);
      va_end (args);
      if (n < 0)
        return -RSE_INTERNAL;
      if (n >= len - i)
        {
          int newlen = len + MEMCHUNK;
          buf = rs_realloc (ctx, buf, newlen);
          if (buf == NULL)
            return -RSE_NOMEM;
          len = newlen;
          continue;
        }
      len -= n;
      i += n;

      *buf_ptr = buf;
      *i_ptr = i;
      *len_ptr = len;
      return RSE_OK;
    }
}
#endif  /* 0 */

static int
pp (char **out, size_t *len, const char *fmt, ...)
{
  int n;
  va_list args;
  va_start (args, fmt);
  n = vsnprintf (*out, *len, fmt, args);
  va_end (args);
  if (n == -1 || n >= *len)
    return -RSE_INTERNAL;
  *out += n;
  *len -= n;
  return RSE_OK;
}

int
rs_context_print_config (struct rs_context *ctx, char **buf_out)
{
  char *buf = rs_malloc (ctx, 8192);
  char *out = NULL;
  size_t len = 8192;
  struct rs_config *cfg = ctx->config;
  struct rs_realm *r = NULL;
  struct rs_peer *p = NULL;
  char *peer_type[] = {"<no type>", "client", "server"};
  char *realm_type[] = {"<no type>", "UDP", "TCP", "TLS", "DTLS"};
  char *cred_type[] = {"<no type>", "PSK", "DHE_PSK", "RSA_PSK"};

  out = buf;
  assert (out);
  assert (cfg);

  for (r = cfg->realms; r != NULL; r = r->next)
    {
      if (pp (&out, &len, "realm %s {\n", r->name)
          || pp (&out, &len, "\ttype = \"%s\"\n\ttimeout = %d\n\tretries = %d\n",
                 realm_type[r->type],
                 r->timeout,
                 r->retries))
        return -RSE_INTERNAL;
      for (p = r->peers; p != NULL; p = p->next)
        {
          if (pp (&out, &len,
                  "\t%s {\n"
                  "\t\thostname = \"%s\"\n"
                  "\t\tservice = \"%s\"\n"
                  "\t\tsecret = \"%s\"\n",
                  peer_type[p->type],
                  p->hostname,
                  p->service,
                  p->secret))
            return -RSE_INTERNAL;
          if (p->cacertfile)
            if (pp (&out, &len, "\t\tcacertfile = \"%s\"\n", p->cacertfile))
              return -RSE_INTERNAL;
          if (p->certfile)
            if (pp (&out, &len, "\t\tcertfile = \"%s\"\n", p->certfile))
              return -RSE_INTERNAL;
          if (p->certkeyfile)
            if (pp (&out, &len, "\t\tcertkeyfile = \"%s\"\n", p->certkeyfile))
              return -RSE_INTERNAL;
          if (p->transport_cred)
            {
              if (pp (&out, &len, "\t\tpskex = \"%s\"\n",
                      cred_type[p->transport_cred->type])
                  || pp (&out, &len, "\t\tpskid = \"%s\"\n",
                         p->transport_cred->identity)
                  || pp (&out, &len,
                         "\t\t%s = \"%s\"\n", (p->transport_cred->secret_encoding
                                               == RS_KEY_ENCODING_ASCII_HEX
                                               ? "pskhexstr" : "pskstr"),
                         p->transport_cred->secret))
                return -RSE_INTERNAL;
            }
          if (pp (&out, &len, "\t}\n"))
            return -RSE_INTERNAL;
        }
      if (pp (&out, &len, "}\n"))
        return -RSE_INTERNAL;
    }

  if (buf_out)
    *buf_out = buf;
  return RSE_OK;
}
