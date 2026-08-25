/* Copyright (c) 2008, UNINETT AS
 * Copyright (c) 2010, NORDUnet A/S */
/* See LICENSE for licensing information. */

#ifndef _TLV_H
#define _TLV_H

#include <stdint.h>

struct tlv {
    uint8_t t;
    uint8_t l;
    uint8_t *v;
};

struct extattrtype {
    uint8_t t;
    uint8_t s;
};

struct tlv *maketlv(uint8_t, uint8_t, void *);
struct tlv *maketlvlongint(uint8_t t, uint32_t v);
struct tlv *makeexttlv(struct extattrtype t, uint8_t l, void *v);
struct tlv *copytlv(struct tlv *);
void freetlv(struct tlv *);
int eqtlv(struct tlv *, struct tlv *);
struct list *copytlvlist(struct list *);
void freetlvlist(struct list *);
void rmtlv(struct list *, uint8_t);
uint8_t *tlv2str(struct tlv *tlv);
struct tlv *resizetlv(struct tlv *, uint8_t);
uint32_t tlv2longint(struct tlv *tlv);
char *tlv2ipv4addr(struct tlv *tlv);

#endif /* _TLV_H */

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
