/*
 * Copyright (C) 2007, 2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <glob.h>
#include <sys/types.h>
#include <libgen.h>
#include <errno.h>
#include "debug.h"
#include "util.h"
#include "gconfig.h"

char *mystringcopyx(const char *s) {
    char *t;
    t = stringcopy(s, 0);
    if (!t)
	debugx(1, DBG_ERR, "malloc failed");
    return t;
}

/* returns NULL on error, where to continue parsing if token and ok. E.g. "" will return token with empty string */
char *strtokenquote(char *s, char **token, char *del, char *quote, char *comment) {
    char *t = s, *q, *r;

    if (!t || !token || !del)
	return NULL;
    while (*t && strchr(del, *t))
	t++;
    if (!*t || (comment && strchr(comment, *t))) {
	*token = NULL;
	return t + 1; /* needs to be non-NULL, but value doesn't matter */
    }
    if (quote && (q = strchr(quote, *t))) {
	t++;
	r = t;
	while (*t && *t != *q)
	    t++;
	if (!*t || (t[1] && !strchr(del, t[1])))
	    return NULL;
	*t = '\0';
	*token = r;
	return t + 1;
    }
    *token = t;
    t++;
    while (*t && !strchr(del, *t))
	t++;
    *t = '\0';
    return t + 1;
}

FILE *pushgconffile(struct gconffile **cf, const char *path) {
    int i;
    struct gconffile *newcf;
    FILE *f;

    f = fopen(path, "r");
    if (!f) {
        debug(DBG_INFO, "could not read config file %s", path);
	return NULL;
    }
    debug(DBG_DBG, "opened config file %s", path);
    if (!*cf) {
	newcf = malloc(sizeof(struct gconffile) * 2);
	if (!newcf)
	    debugx(1, DBG_ERR, "malloc failed");
	newcf[1].file = NULL;
	newcf[1].path = NULL;
    } else {
	for (i = 0; (*cf)[i].path; i++);
	newcf = realloc(*cf, sizeof(struct gconffile) * (i + 2));
	if (!newcf)
	    debugx(1, DBG_ERR, "malloc failed");
	memmove(newcf + 1, newcf, sizeof(struct gconffile) * (i + 1));
    }
    newcf[0].file = f;
    newcf[0].path = mystringcopyx(path);
    *cf = newcf;
    return f;
}

FILE *pushgconffiles(struct gconffile **cf, const char *cfgpath) {
    int i;
    FILE *f = NULL;
    glob_t globbuf;
    char *path, *curfile = NULL, *dir;
    
    /* if cfgpath is relative, make it relative to current config */
    if (*cfgpath == '/')
	path = (char *)cfgpath;
    else {
	/* dirname may modify its argument */
	curfile = mystringcopyx((*cf)->path);
	dir = dirname(curfile);
	path = malloc(strlen(dir) + strlen(cfgpath) + 2);
	if (!path)
	    debugx(1, DBG_ERR, "malloc failed");
	strcpy(path, dir);
	path[strlen(dir)] = '/';
	strcpy(path + strlen(dir) + 1, cfgpath);
    }
    memset(&globbuf, 0, sizeof(glob_t));
    if (glob(path, 0, NULL, &globbuf))
	debug(DBG_INFO, "could not glob %s", path);
    else {
	for (i = globbuf.gl_pathc - 1; i >= 0; i--) {
	    f = pushgconffile(cf, globbuf.gl_pathv[i]);
	    if (!f)
		break;
	}    
	globfree(&globbuf);
    }
    if (curfile) {
	free(curfile);
	free(path);
    }
    return f;
}

FILE *popgconffile(struct gconffile **cf) {
    int i;

    if (!*cf)
	return NULL;
    for (i = 0; (*cf)[i].path; i++);
    if (i && (*cf)[0].file) {
	fclose((*cf)[0].file);
	debug(DBG_DBG, "closing config file %s", (*cf)[0].path);
	free((*cf)[0].path);
    }
    if (i < 2) {
	free(*cf);
	*cf = NULL;
	return NULL;
    }
    memmove(*cf, *cf + 1, sizeof(struct gconffile) * i);
    return (*cf)[0].file;
}

struct gconffile *openconfigfile(const char *file) {
    struct gconffile *cf = NULL;

    if (!pushgconffile(&cf, file))
	debugx(1, DBG_ERR, "could not read config file %s\n%s", file, strerror(errno));
    debug(DBG_DBG, "reading config file %s", file);
    return cf;
}

/* Parses config with following syntax:
 * One of these:
 * option-name value
 * option-name = value
 * Or:
 * option-name value {
 *     option-name [=] value
 *     ...
 * }
 */

void getconfigline(struct gconffile **cf, char *block, char **opt, char **val, int *conftype) {
    char line[1024];
    char *tokens[3], *s;
    int tcount;
    
    *opt = NULL;
    *val = NULL;
    *conftype = 0;
    
    if (!cf || !*cf || !(*cf)->file)
	return;

    for (;;) {
	if (!fgets(line, 1024, (*cf)->file)) {
	    if (popgconffile(cf))
		continue;
	    return;
	}
	s = line;
	for (tcount = 0; tcount < 3; tcount++) {
	    s = strtokenquote(s, &tokens[tcount], " \t\r\n", "\"'", tcount ? NULL : "#");
	    if (!s)
		debugx(1, DBG_ERR, "Syntax error in line starting with: %s", line);
	    if (!tokens[tcount])
		break;
	}
	if (!tcount || **tokens == '#')
	    continue;

	if (**tokens == '}') {
	    if (block)
		return;
	    debugx(1, DBG_ERR, "configuration error, found } with no matching {");
	}
	break;
    }
    
    switch (tcount) {
    case 2:
	*opt = mystringcopyx(tokens[0]);
	*val = mystringcopyx(tokens[1]);
	*conftype = CONF_STR;
	break;
    case 3:
	if (tokens[1][0] == '=' && tokens[1][1] == '\0') {
	    *opt = mystringcopyx(tokens[0]);
	    *val = mystringcopyx(tokens[2]);
	    *conftype = CONF_STR;
	    break;
	}
	if (tokens[2][0] == '{' && tokens[2][1] == '\0') {
	    *opt = mystringcopyx(tokens[0]);
	    *val = mystringcopyx(tokens[1]);
	    *conftype = CONF_CBK;
	    break;
	}
	/* fall through */
    default:
	if (block)
	    debugx(1, DBG_ERR, "configuration error in block %s, line starting with %s", block, tokens[0]);
	debugx(1, DBG_ERR, "configuration error, syntax error in line starting with %s", tokens[0]);
    }

    if (!**val)
	debugx(1, DBG_ERR, "configuration error, option %s needs a non-empty value", *opt);
    return;
}

void getgenericconfig(struct gconffile **cf, char *block, ...) {
    va_list ap;
    char *opt = NULL, *val, *word, *optval, **str = NULL, ***mstr = NULL, *endptr;
    uint8_t *bln = NULL;
    long int *lint = NULL;
    int type = 0, conftype = 0, n;
    void (*cbk)(struct gconffile **, char *, char *, char *) = NULL;

    for (;;) {
	free(opt);
	getconfigline(cf, block, &opt, &val, &conftype);
	if (!opt)
	    return;

	if (conftype == CONF_STR && !strcasecmp(opt, "include")) {
	    if (!pushgconffiles(cf, val))
		debugx(1, DBG_ERR, "failed to include config file %s", val);
	    free(val);
	    continue;
	}
	    
	va_start(ap, block);
	while ((word = va_arg(ap, char *))) {
	    type = va_arg(ap, int);
	    switch (type) {
	    case CONF_STR:
		str = va_arg(ap, char **);
		if (!str)
		    debugx(1, DBG_ERR, "getgenericconfig: internal parameter error");
		break;
	    case CONF_MSTR:
		mstr = va_arg(ap, char ***);
		if (!mstr)
		    debugx(1, DBG_ERR, "getgenericconfig: internal parameter error");
		break;
	    case CONF_BLN:
		bln = va_arg(ap, uint8_t *);
		if (!bln)
		    debugx(1, DBG_ERR, "getgenericconfig: internal parameter error");
		break;
	    case CONF_LINT:
		lint = va_arg(ap, long int *);
		if (!lint)
		    debugx(1, DBG_ERR, "getgenericconfig: internal parameter error");
		break;
	    case CONF_CBK:
		cbk = va_arg(ap, void (*)(struct gconffile **, char *, char *, char *));
		break;
	    default:
		debugx(1, DBG_ERR, "getgenericconfig: internal parameter error");
	    }
	    if (!strcasecmp(opt, word))
		break;
	}
	va_end(ap);
	
	if (!word) {
	    if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, unknown option %s", block, opt);
	    debugx(1, DBG_ERR, "configuration error, unknown option %s", opt);
	}

	if (((type == CONF_STR || type == CONF_MSTR || type == CONF_BLN || type == CONF_LINT) && conftype != CONF_STR) ||
	    (type == CONF_CBK && conftype != CONF_CBK)) {
	    if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, wrong syntax for option %s", block, opt);
	    debugx(1, DBG_ERR, "configuration error, wrong syntax for option %s", opt);
	}

	switch (type) {
	case CONF_STR:
	    if (*str)
		debugx(1, DBG_ERR, "configuration error, option %s already set to %s", opt, *str);
	    *str = val;
	    break;
	case CONF_MSTR:
	    if (*mstr)
		for (n = 0; (*mstr)[n]; n++);
	    else
		n = 0;
	    *mstr = realloc(*mstr, sizeof(char *) * (n + 2));
	    if (!*mstr)
		debugx(1, DBG_ERR, "malloc failed");
	    (*mstr)[n] = val;
	    (*mstr)[n + 1] = NULL;
	    break;
	case CONF_BLN:
	    if (!strcasecmp(val, "on"))
		*bln = 1;
	    else if (!strcasecmp(val, "off"))
		*bln = 0;
	    else if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, value for option %s must be on or off, not %s", block, opt, val);
	    else
		debugx(1, DBG_ERR, "configuration error, value for option %s must be on or off, not %s", opt, val);
	    break;
	case CONF_LINT:
	    endptr = NULL;
	    *lint = strtol(val, &endptr, 0);
	    if (*lint == LONG_MIN || *lint == LONG_MAX || !endptr || endptr == val || *endptr != '\0') {
		if (block)
		    debugx(1, DBG_ERR, "configuration error in block %s, value for option %s must be an integer, not %s", block, opt, val);
		else
		    debugx(1, DBG_ERR, "configuration error, value for option %s must be an integer, not %s", opt, val);
	    }
	    break;
	case CONF_CBK:
	    optval = malloc(strlen(opt) + strlen(val) + 2);
	    if (!optval)
		debugx(1, DBG_ERR, "malloc failed");
	    sprintf(optval, "%s %s", opt, val);
	    cbk(cf, optval, opt, val);
	    free(val);
	    free(optval);
	    continue;
	default:
	    debugx(1, DBG_ERR, "getgenericconfig: internal parameter error");
	}
	if (block)
	    debug(DBG_DBG, "getgenericconfig: block %s: %s = %s", block, opt, val);
	else 
	    debug(DBG_DBG, "getgenericconfig: %s = %s", opt, val);
	if (type == CONF_BLN || type == CONF_LINT)
	    free(val);
    }
}
