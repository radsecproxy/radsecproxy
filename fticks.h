/* Copyright (C) 2011 NORDUnet A/S
 * See LICENSE for information about licensing.
 */

int fticks_configure(struct options *options,
		     uint8_t **reportingp,
		     uint8_t **macp,
		     uint8_t **keyp);
int fticks_hashmac(const uint8_t *in,
		   const uint8_t *key,
		   size_t out_len,
		   uint8_t *out);
void fticks_log(const struct options *options,
		const struct client *client,
		const struct radmsg *msg,
		const struct rqout *rqout);
