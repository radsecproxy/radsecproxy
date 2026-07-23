/* Copyright (c) 2026, Nova Labs */
/* See LICENSE for licensing information. */

/* Regular (forward) CoA/Disconnect proxying per RFC 5176 and RFC 8559. */

#ifndef _COA_H
#define _COA_H

#include "radmsg.h"
#include "radsecproxy.h"

char *extract_operator_realm(struct radmsg *msg, char *buf, size_t bufsize);

struct server *findcoaserver(struct list *realmlist, struct realm **realm, struct radmsg *msg, int *nasmismatch);

struct tlv *make_error_cause_tlv(uint32_t cause);

uint8_t coa_nak_code(uint8_t requestcode);

int event_timestamp_fresh(struct tlv *attr, uint8_t window);

#endif /* _COA_H */

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
