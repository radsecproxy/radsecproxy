/*
 * Copyright (C) 2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

void tcpsetsrcres(char *source);
int tcpconnect(struct server *server, struct timeval *when, int timeout, char *text);
int clientradputtcp(struct server *server, unsigned char *rad);
void *tcpclientrd(void *arg);
void *tcplistener(void *arg);
