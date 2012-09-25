/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <stdint.h>
#include <stddef.h>

int fticks_hashmac(const uint8_t *in,
		   const uint8_t *key,
		   size_t out_len,
		   uint8_t *out);
