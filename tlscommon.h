/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)
struct tls *tlsgettls(char *alt1, char *alt2);
SSL_CTX *tlsgetctx(uint8_t type, struct tls *t);
int conftls_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
#endif
