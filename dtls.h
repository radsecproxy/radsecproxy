/*
 * Copyright (C) 2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

void *udpdtlsserverrd(void *arg);
int dtlsconnect(struct server *server, struct timeval *when, int timeout, char *text);
void *dtlsservernew(void *arg);
void *dtlsclientrd(void *arg);
void *udpdtlsclientrd(void *arg);
int clientradputdtls(struct server *server, unsigned char *rad);
void addserverextradtls(struct clsrvconf *conf);
void initextradtls();
