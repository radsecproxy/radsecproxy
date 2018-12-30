/* Copyright (c) 2019, SWITCH */
/* See LICENSE for licensing information. */

struct modattr {
    uint8_t t;
    char *replacement;
    regex_t *regex;
};

struct rewrite {
    uint8_t *removeattrs;
    uint32_t *removevendorattrs;
    struct list *addattrs;
    struct list *modattrs;
    struct list *supattrs;
};

int confrewrite_cb(struct gconffile **cf, void *arg, char *block, char *opt, char *val);
int dorewrite(struct radmsg *msg, struct rewrite *rewrite);
struct modattr *extractmodattr(char *nameval);
struct rewrite *getrewrite(char *alt1, char *alt2);
int resizeattr(struct tlv *attr, uint8_t newlen);

int dorewritemodattr(struct tlv *attr, struct modattr *modattr);
int addvendorattr(struct radmsg *msg, uint32_t vendor, struct tlv *attr);


/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
