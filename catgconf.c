/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "debug.h"
#include "gconfig.h"

int listconfig(struct gconffile **cf, char *block, int compact) {
    char *opt = NULL, *val = NULL;
    int conftype;

    for (;;) {
	free(opt);
	free(val);
	if (!getconfigline(cf, block, &opt, &val, &conftype))
            return -1;
        if (!opt)
            return 0;           /* Success.  */

	if (conftype == CONF_STR && !strcasecmp(opt, "include")) {
	    if (!pushgconfpaths(cf, val))
		debugx(1, DBG_ERR, "failed to include config file %s", val);
	    continue;
	}

	switch (conftype) {
	case CONF_STR:
	    if (block)
		printf(compact ? "%s=%s;" : "\t%s=%s\n", opt, val);
	    else
		printf("%s=%s\n", opt, val);
	    break;
	case CONF_CBK:
	    printf("%s %s {%s", opt, val, compact ? "" : "\n");
	    if (listconfig(cf, val, compact))
                return -1;
	    printf("}\n");
	    break;
	default:
	    printf("Unsupported config type\n");
            return -1;
	}
    }

    return 0;                   /* Success.  */
}

int main(int argc, char **argv) {
    int c, compact = 0;
    struct gconffile *cfs;

    debug_init("radsecproxy-conf");
    debug_set_level(DBG_WARN);

    while ((c = getopt(argc, argv, "c")) != -1) {
	switch (c) {
        case 'c':
	    compact = 1;
            break;
	default:
	    goto usage;
	}
    }
    if (argc - optind != 1)
        goto usage;

    cfs = openconfigfile(argv[optind]);
    return listconfig(&cfs, NULL, compact);

usage:
    debug(DBG_ERR, "Usage:\n%s [ -c ] configfile", argv[0]);
    exit(1);
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
