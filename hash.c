/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "list.h"
#include "hash.h"

/* allocates and initialises hash structure; returns NULL if malloc fails */
struct hash *hash_create() {
    struct hash *h = malloc(sizeof(struct hash));
    if (!h)
	return NULL;
    h->hashlist = list_create();
    if (!h->hashlist) {
	free(h);
	return NULL;
    }
    pthread_mutex_init(&h->mutex, NULL);
    return h;
}

/* frees all memory associated with the hash */
void hash_destroy(struct hash *h) {
    struct list_node *ln;

    if (!h)
	return;
    for (ln = list_first(h->hashlist); ln; ln = list_next(ln)) {
	free(((struct hash_entry *)ln->data)->key);
	free(((struct hash_entry *)ln->data)->data);
    }
    list_destroy(h->hashlist);
    pthread_mutex_destroy(&h->mutex);
}

/* insert entry in hash; returns 1 if ok, 0 if malloc fails */
int hash_insert(struct hash *h, void *key, uint32_t keylen, void *data) {
    struct hash_entry *e;

    if (!h)
	return 0;
    e = malloc(sizeof(struct hash_entry));
    if (!e)
	return 0;
    memset(e, 0, sizeof(struct hash_entry));
    e->key = malloc(keylen);
    if (!e->key) {
	free(e);
	return 0;
    }
    memcpy(e->key, key, keylen);
    e->keylen = keylen;
    e->data = data;
    pthread_mutex_lock(&h->mutex);
    if (!list_push(h->hashlist, e)) {
	pthread_mutex_unlock(&h->mutex);
	free(e->key);
	free(e);
	return 0;
    }
    pthread_mutex_unlock(&h->mutex);
    return 1;
}

/* reads entry from hash */
void *hash_read(struct hash *h, void *key, uint32_t keylen) {
    struct list_node *ln;
    struct hash_entry *e;

    if (!h)
	return 0;
    pthread_mutex_lock(&h->mutex);
    for (ln = list_first(h->hashlist); ln; ln = list_next(ln)) {
	e = (struct hash_entry *)ln->data;
	if (e->keylen == keylen && !memcmp(e->key, key, keylen)) {
	    pthread_mutex_unlock(&h->mutex);
	    return e->data;
	}
    }
    pthread_mutex_unlock(&h->mutex);
    return NULL;
}

/* extracts entry from hash */
void *hash_extract(struct hash *h, void *key, uint32_t keylen) {
    struct list_node *ln;
    struct hash_entry *e;

    if (!h)
	return 0;
    pthread_mutex_lock(&h->mutex);
    for (ln = list_first(h->hashlist); ln; ln = list_next(ln)) {
	e = (struct hash_entry *)ln->data;
	if (e->keylen == keylen && !memcmp(e->key, key, keylen)) {
	    free(e->key);
	    list_removedata(h->hashlist, e);
	    free(e);
	    pthread_mutex_unlock(&h->mutex);
	    return e->data;
	}
    }
    pthread_mutex_unlock(&h->mutex);
    return NULL;
}

/* returns first entry */
struct hash_entry *hash_first(struct hash *hash) {
    struct list_node *ln;
    struct hash_entry *e;
    if (!hash || !((ln = list_first(hash->hashlist))))
	return NULL;
    e = (struct hash_entry *)ln->data;
    e->next = ln->next;
    return e;
}

/* returns the next node after the argument */
struct hash_entry *hash_next(struct hash_entry *entry) {
    struct hash_entry *e;
    if (!entry || !entry->next)
	return NULL;
    e = (struct hash_entry *)entry->next->data;
    e->next = (struct list_node *)entry->next->next;
    return e;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
