/*
 * Copyright (C) 2007 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "debug.h"
#include "util.h"
#include "gconfig.h"

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
    if (!*cf) {
	newcf = malloc(sizeof(struct gconffile) * 2);
	if (!newcf)
	    debugx(1, DBG_ERR, "malloc failed");
	newcf[1].path = NULL;
    } else {
	for (i = 0; (*cf)[i].path; i++);
	newcf = realloc(*cf, sizeof(struct gconffile) * (i + 2));
	if (!newcf)
	    debugx(1, DBG_ERR, "malloc failed");
	memmove(newcf + 1, newcf, sizeof(struct gconffile) * (i + 1));
    }
    newcf[0].file = f;
    newcf[0].path = stringcopy(path, 0);
    *cf = newcf;
    return f;
}

FILE *popgconffile(struct gconffile **cf) {
    int i;

    if (!*cf)
	return NULL;
    for (i = 0; (*cf)[i].path; i++);
    if (i && (*cf)[0].file)
	fclose((*cf)[0].file);
    if (i < 2) {
	free(*cf);
	*cf = NULL;
	return NULL;
    }
    memmove(*cf, *cf + 1, sizeof(struct gconffile) * i);
    return (*cf)[0].file;
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
void getgenericconfig(FILE *f, char *block, ...) {
    va_list ap;
    char line[1024];
    /* initialise lots of stuff to avoid stupid compiler warnings */
    char *tokens[3], *s, *opt = NULL, *val = NULL, *word, *optval, **str = NULL, ***mstr = NULL;
    int type = 0, tcount, conftype = 0, n;
    void (*cbk)(FILE *, char *, char *, char *) = NULL;
	
    while (fgets(line, 1024, f)) {
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

	switch (tcount) {
	case 2:
	    opt = tokens[0];
	    val = tokens[1];
	    conftype = CONF_STR;
	    break;
	case 3:
	    if (tokens[1][0] == '=' && tokens[1][1] == '\0') {
		opt = tokens[0];
		val = tokens[2];
		conftype = CONF_STR;
		break;
	    }
	    if (tokens[2][0] == '{' && tokens[2][1] == '\0') {
		opt = tokens[0];
		val = tokens[1];
		conftype = CONF_CBK;
		break;
	    }
	    /* fall through */
	default:
	    if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, line starting with %s", block, tokens[0]);
	    debugx(1, DBG_ERR, "configuration error, syntax error in line starting with %s", tokens[0]);
	}

	if (!*val)
	    debugx(1, DBG_ERR, "configuration error, option %s needs a non-empty value", opt);
	
	va_start(ap, block);
	while ((word = va_arg(ap, char *))) {
	    type = va_arg(ap, int);
	    switch (type) {
	    case CONF_STR:
		str = va_arg(ap, char **);
		if (!str)
		    debugx(1, DBG_ERR, "getgeneralconfig: internal parameter error");
		break;
	    case CONF_MSTR:
		mstr = va_arg(ap, char ***);
		if (!mstr)
		    debugx(1, DBG_ERR, "getgeneralconfig: internal parameter error");
		break;
	    case CONF_CBK:
		cbk = va_arg(ap, void (*)(FILE *, char *, char *, char *));
		break;
	    default:
		debugx(1, DBG_ERR, "getgeneralconfig: internal parameter error");
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

	if (((type == CONF_STR || type == CONF_MSTR) && conftype != CONF_STR) ||
	    (type == CONF_CBK && conftype != CONF_CBK)) {
	    if (block)
		debugx(1, DBG_ERR, "configuration error in block %s, wrong syntax for option %s", block, opt);
	    debugx(1, DBG_ERR, "configuration error, wrong syntax for option %s", opt);
	}

	switch (type) {
	case CONF_STR:
	    if (block)
		debug(DBG_DBG, "getgeneralconfig: block %s: %s = %s", block, opt, val);
	    else 
		debug(DBG_DBG, "getgeneralconfig: %s = %s", opt, val);
	    if (*str)
		debugx(1, DBG_ERR, "configuration error, option %s already set to %s", opt, *str);
	    *str = stringcopy(val, 0);
	    if (!*str)
		debugx(1, DBG_ERR, "malloc failed");
	    break;
	case CONF_MSTR:
	    if (block)
		debug(DBG_DBG, "getgeneralconfig: block %s: %s = %s", block, opt, val);
	    else 
		debug(DBG_DBG, "getgeneralconfig: %s = %s", opt, val);
	    if (*mstr)
		for (n = 0; (*mstr)[n]; n++);
	    else
		n = 0;
	    *mstr = realloc(*mstr, sizeof(char *) * (n + 2));
	    if (!*mstr)
		debugx(1, DBG_ERR, "malloc failed");
	    (*mstr)[n] = stringcopy(val, 0);
	    (*mstr)[n + 1] = NULL;
	    break;
	case CONF_CBK:
	    optval = malloc(strlen(opt) + strlen(val) + 2);
	    if (!optval)
		debugx(1, DBG_ERR, "malloc failed");
	    sprintf(optval, "%s %s", opt, val);
	    cbk(f, optval, opt, val);
	    free(optval);
	    break;
	default:
	    debugx(1, DBG_ERR, "getgeneralconfig: internal parameter error");
	}
    }
}
