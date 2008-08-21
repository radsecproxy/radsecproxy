/*
 * Copyright (C) 2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <stdint.h>

struct hash {
    struct list *hashlist;
    pthread_mutex_t mutex;
};

/* allocates and initialises hash structure; returns NULL if malloc fails */
struct hash *hash_create();

/* frees all memory associated with the hash */
void hash_destroy(struct hash *hash);

/* insert entry in hash; returns 1 if ok, 0 if malloc fails */
int hash_insert(struct hash *hash, void *key, uint32_t keylen, void *data);

/* reads entry from hash */
void *hash_read(struct hash *hash, void *key, uint32_t keylen);
