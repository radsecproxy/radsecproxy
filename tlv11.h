/*
 * Copyright (C) 2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

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
