/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

int tlsconnect(struct server *server, struct timeval *when, int timeout, char *text);
int clientradputtls(struct server *server, unsigned char *rad);
void *tlsclientrd(void *arg);
void *tlslistener(void *arg);
