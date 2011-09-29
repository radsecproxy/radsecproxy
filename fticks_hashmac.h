/* Copyright (C) 2011 NORDUnet A/S
 * See LICENSE for information about licensing.
 */

#include <stdint.h>
#include <stddef.h>

int fticks_hashmac(const uint8_t *in,
		   const uint8_t *key,
		   size_t out_len,
		   uint8_t *out);
