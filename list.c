#include <stdlib.h>
#include <string.h>
#include "list.h"

/* allocates and initialises list structure; returns NULL if malloc fails */
struct list *list_create() {
    struct list *list = malloc(sizeof(struct list));
    if (list)
	memset(list, 0, sizeof(struct list));
    return list;
}

/* frees all memory associated with the list */
void list_destroy(struct list *list) {
    struct list_node *node, *next;

    if (!list)
	return;
    
    for (node = list->first; node; node = next) {
	free(node->data);
	next = node->next;
	free(node);
    }
    free(list);
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
    
    return 1;
}

/* removes first entry from list and returns data */
void *list_shift(struct list *list) {
    struct list_node *node;
    void *data;
    
    if (!list->first)
	return NULL;
    
    node = list->first;
    list->first = node->next;
    if (!list->first)
	list->last = NULL;
    data = node->data;
    free(node);
    
    return data;
}

/* removes first entry with matching data pointer */
void list_removedata(struct list *list, void *data) {
    struct list_node *node, *t;
    
    if (!list->first)
	return;

    node = list->first;
    if (node->data == data) {
	list->first = node->next;
	if (!list->first)
	    list->last = NULL;
	free(node);
	return;
    }
    for (; node->next; node = node->next)
	if (node->next->data == data) {
	    t = node->next;
	    node->next = node->next->next;
	    if (!node->next) /* we removed the last one */
		list->last = node;
	    free(t);
	    return;
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
