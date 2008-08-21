/*
 * Copyright (C) 2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "list.h"
#include "hash.h"

struct entry {
    void *key;
    uint32_t keylen;
    void *data;
};
	
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
	free(((struct entry *)ln->data)->key);
	free(((struct entry *)ln->data)->data);
    }
    list_destroy(h->hashlist);
    pthread_mutex_destroy(&h->mutex);
}

/* insert entry in hash; returns 1 if ok, 0 if malloc fails */
int hash_insert(struct hash *h, void *key, uint32_t keylen, void *data) {
    struct entry *e;

    if (!h)
	return 0;
    e = malloc(sizeof(struct entry));
    if (!e)
	return 0;
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
    struct entry *e;
    
    if (!h)
	return 0;
    pthread_mutex_lock(&h->mutex);
    for (ln = list_first(h->hashlist); ln; ln = list_next(ln)) {
	e = (struct entry *)ln->data;
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
    struct entry *e;
    
    if (!h)
	return 0;
    pthread_mutex_lock(&h->mutex);
    for (ln = list_first(h->hashlist); ln; ln = list_next(ln)) {
	e = (struct entry *)ln->data;
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
