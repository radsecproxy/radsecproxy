/* Copyright (c) 2011, NORDUnet A/S */
/* See LICENSE for licensing information. */

int fticks_configure(struct options *options,
		     uint8_t **reportingp,
		     uint8_t **macp,
		     uint8_t **keyp);
void fticks_log(const struct options *options,
		const struct client *client,
		const struct radmsg *msg,
		const struct request *rq);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
