#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "debug.h"
#include "gconfig.h"

void listconfig(struct gconffile **cf, char *block, int compact) {
    char *opt = NULL, *val = NULL;
    int conftype;

    for (;;) {
	free(opt);
	free(val);
	getconfigline(cf, block, &opt, &val, &conftype);
	if (!opt)
	    return;

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
	    listconfig(cf, val, compact);
	    printf("}\n");
	    break;
	default:
	    printf("Unsupported config type\n");
	}
    }
}

int main(int argc, char **argv) {
    int c, compact = 0;
    struct gconffile *cfs;

    debug_init("catgconf");
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
    listconfig(&cfs, NULL, compact);
    return 0;

usage:
    debug(DBG_ERR, "Usage:\n%s [ -c ] configfile", argv[0]);
    exit(1);
}
