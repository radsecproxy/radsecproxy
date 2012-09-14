/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

int fticks_configure(struct options *options,
		     uint8_t **reportingp,
		     uint8_t **macp,
		     uint8_t **keyp);
void fticks_log(const struct options *options,
		const struct client *client,
		const struct radmsg *msg,
		const struct rqout *rqout);
