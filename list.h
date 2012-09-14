/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#ifdef SYS_SOLARIS9
#include <sys/inttypes.h>
#else
#include <stdint.h>
#endif

struct list_node {
    struct list_node *next;
    void *data;
};

struct list {
    struct list_node *first, *last;
    uint32_t count;
};

/* allocates and initialises list structure; returns NULL if malloc fails */
struct list *list_create();

/* frees all memory associated with the list */
void list_destroy(struct list *list);

/* appends entry to list; returns 1 if ok, 0 if malloc fails */
int list_push(struct list *list, void *data);

/* removes first entry from list and returns data */
void *list_shift(struct list *list);

/* removes first entry with matching data pointer */
void list_removedata(struct list *list, void *data);

/* returns first node */
struct list_node *list_first(struct list *list);

/* returns the next node after the argument */
struct list_node *list_next(struct list_node *node);

/* returns number of nodes */
uint32_t list_count(struct list *list);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
