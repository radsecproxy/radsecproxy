/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

struct tlv {
    uint8_t t;
    uint8_t l;
    uint8_t *v;
};

struct tlv *maketlv(uint8_t, uint8_t, void *);
struct tlv *copytlv(struct tlv *);
void freetlv(struct tlv *);
int eqtlv(struct tlv *, struct tlv *);
struct list *copytlvlist(struct list *);
void freetlvlist(struct list *);
void rmtlv(struct list *, uint8_t);
uint8_t *tlv2str(struct tlv *tlv);
uint8_t *tlv2buf(uint8_t *, const struct tlv *tlv);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
