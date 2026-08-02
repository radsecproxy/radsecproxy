/* Copyright (c) 2019, SWITCH */
/* See LICENSE for licensing information. */

#ifndef _REWRITE_H
#define _REWRITE_H

#include "list.h"
#include "radmsg.h"
#include <regex.h>

struct sockaddr;

struct modattr {
    uint8_t t;
    uint32_t vendor;
    char *replacement;
    regex_t *regex;
};

struct dynattr {
    uint8_t t;
    uint32_t vendor;
    char *field;
};

struct rewrite_context {
    struct sockaddr *clientaddr;
    char *clientname;
};

struct rewrite {
    uint8_t whitelist_mode;
    uint8_t *removeattrs;        /*NULL terminated*/
    uint32_t *removevendorattrs; /*NULL terminated*/
    struct list *addattrs;       /*struct tlv*/
    struct list *modattrs;       /*struct modattr*/
    struct list *modvattrs;      /*struct modattr*/
    struct list *supattrs;       /*struct tlv*/
    struct list *addmetaattrs;   /*struct dynattr*/
    struct list *supmetaattrs;   /*struct dynattr*/
};

void addrewrite(char *value, uint8_t whitelist_mode, char **rmattrs, char **rmvattrs, char **addattrs,
                char **addvattrs, char **modattrs, char **modvattrs, char **supattrs, char **supvattrs,
                char **addmetaattrs, char **addmetavattrs, char **supmetaattrs, char **supmetavattrs);
int dorewrite(struct radmsg *msg, struct rewrite *rewrite, struct rewrite_context *ctx);
struct modattr *extractmodattr(char *nameval);
struct dynattr *extractdynattr(char *nameval, char vendor_flag);
struct rewrite *getrewrite(char *alt1, char *alt2);

int dorewritemodattr(struct tlv *attr, struct modattr *modattr);
void dorewriterm(struct radmsg *msg, uint8_t *rmattrs, uint32_t *rmvattrs, int inverted);
int addvendorattr(struct radmsg *msg, uint32_t vendor, struct tlv *attr);

#endif /*_REWRITE_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
