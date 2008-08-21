/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

int clientradputudp(struct server *server, unsigned char *rad);
void *udpclientrd(void *arg);
void *udpserverrd(void *arg);
void *udpserverwr(void *arg);
