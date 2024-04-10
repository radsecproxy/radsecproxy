/* Copyright (c) 2007-2009, UNINETT AS */
/* See LICENSE for licensing information. */

#include <stdlib.h>
#include <string.h>
#include "list.h"

/* Private helper functions. */
static void list_free_helper_(struct list *list, int free_data_flag) {
    struct list_node *node, *next;

    if (!list)
	return;

    for (node = list->first; node; node = next) {
        if (free_data_flag)
            free(node->data);
	next = node->next;
	free(node);
    }
    free(list);
}

/* Public functions. */

/* allocates and initialises list structure; returns NULL if malloc fails */
struct list *list_create(void) {
    struct list *list = malloc(sizeof(struct list));
    if (list)
	memset(list, 0, sizeof(struct list));
    return list;
}

/* frees all memory associated with the list
   note that the data pointed at from each node is also freed
   use list_free() to free only the memory used by the list itself */
void list_destroy(struct list *list) {
    list_free_helper_(list, 1);
}

/* frees the meory used by the list itself
   note that the data pointed at from each node is not freed
   use list_destroy() to free all the data associated with the list */
void list_free(struct list *list) {
    list_free_helper_(list, 0);
}

/* appends entry to list; returns 1 if ok, 0 if malloc fails */
int list_push(struct list *list, void *data) {
    struct list_node *node;

    node = malloc(sizeof(struct list_node));
    if (!node)
	return 0;

    node->next = NULL;
    node->data = data;

    if (list->first)
	list->last->next = node;
    else
	list->first = node;
    list->last = node;

    list->count++;
    return 1;
}

/* insert entry at front of the list; returns 1 if ok, 0 if malloc fails */
int list_push_front(struct list *list, void *data) {
    struct list_node *node;

    node = malloc(sizeof(struct list_node));
    if (!node)
        return 0;

    node->data = data;
    node->next = list->first;
    if (!list->first)
        list->last = node;
    list->first = node;
    list->count++;
    return 1;
}

/* removes first entry from list and returns data */
void *list_shift(struct list *list) {
    struct list_node *node;
    void *data;

    if (!list || !list->first)
	return NULL;

    node = list->first;
    list->first = node->next;
    if (!list->first)
	list->last = NULL;
    data = node->data;
    free(node);
    list->count--;
    return data;
}

/* removes all entries with matching data pointer */
void list_removedata(struct list *list, void *data) {
    struct list_node *node, *t;

    if (!list || !list->first)
	return;

    node = list->first;
    while (node->data == data) {
	list->first = node->next;
	free(node);
	list->count--;
	node = list->first;
	if (!node) {
	    list->last = NULL;
	    return;
	}
    }
    for (; node->next; node = node->next)
	if (node->next->data == data) {
	    t = node->next;
	    node->next = t->next;
	    free(t);
	    list->count--;
	    if (!node->next) { /* we removed the last one */
		list->last = node;
		return;
	    }
	}
}

/* returns first node */
struct list_node *list_first(struct list *list) {
    return list ? list->first : NULL;
}

/* returns the next node after the argument */
struct list_node *list_next(struct list_node *node) {
    return node->next;
}

/* returns number of nodes */
uint32_t list_count(struct list *list) {
    return list->count;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
