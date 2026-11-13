/* Copyright (c) 2008, UNINETT AS */
/* See LICENSE for licensing information. */

const struct protodefs *udpinit(uint8_t h);
int udplistenersocket(int family);
struct client *findreversecoaclient(struct clsrvconf *p, int sock, struct sockaddr *from, const uint8_t *buf, int len);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
