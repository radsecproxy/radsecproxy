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
    data = node->data;
    free(node);
    
    return data;
}

/* returns first node */
struct list_node *list_first(struct list *list) {
    return list->first;
}

/* returns the next node after the argument */
struct list_node *list_next(struct list_node *node) {
    return node->next;
}
