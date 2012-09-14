/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <glob.h>
#include <sys/types.h>
#include <ctype.h>
#include <libgen.h>
#include <errno.h>
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

int pushgconfdata(struct gconffile **cf, const char *data) {
    int i;
    struct gconffile *newcf;

    if (!*cf) {
	newcf = malloc(sizeof(struct gconffile) * 2);
	if (!newcf)
	    return 0;
	memset(newcf, 0, sizeof(struct gconffile) * 2);
    } else {
	for (i = 0; (*cf)[i].data || (*cf)[i].path; i++);
	newcf = realloc(*cf, sizeof(struct gconffile) * (i + 2));
	if (!newcf)
	    return 0;
	memmove(newcf + 1, newcf, sizeof(struct gconffile) * (i + 1));
	memset(newcf, 0, sizeof(struct gconffile));
    }
    newcf[0].data = data;
    *cf = newcf;
    return 1;
}

FILE *pushgconffile(struct gconffile **cf, FILE *file, const char *description) {
    int i;
    struct gconffile *newcf;
    char *desc;

    if (!file) {
        debug(DBG_INFO, "could not read config from %s", description);
	return NULL;
    }
    debug(DBG_DBG, "reading config from %s", description);

    desc = stringcopy(description, 0);
    if (!desc)
	goto errmalloc;

    if (!*cf) {
	newcf = malloc(sizeof(struct gconffile) * 2);
	if (!newcf)
	    goto errmalloc;
	memset(newcf, 0, sizeof(struct gconffile) * 2);
    } else {
	for (i = 0; (*cf)[i].data || (*cf)[i].path; i++);
	newcf = realloc(*cf, sizeof(struct gconffile) * (i + 2));
	if (!newcf)
	    goto errmalloc;
	memmove(newcf + 1, newcf, sizeof(struct gconffile) * (i + 1));
	memset(newcf, 0, sizeof(struct gconffile));
    }
    newcf[0].file = file;
    newcf[0].path = desc;
    *cf = newcf;
    return file;

errmalloc:
    free(desc);
    fclose(file);
    debug(DBG_ERR, "malloc failed");
    return NULL;
}

FILE *pushgconfpath(struct gconffile **cf, const char *path) {
    FILE *f;

    f = fopen(path, "r");
    return pushgconffile(cf, f, path);
}

FILE *pushgconfpaths(struct gconffile **cf, const char *cfgpath) {
    int i;
    FILE *f = NULL;
    glob_t globbuf;
    char *path, *curfile = NULL, *dir;

    /* if cfgpath is relative, make it relative to current config */
    if (*cfgpath == '/')
	path = (char *)cfgpath;
    else {
	/* dirname may modify its argument */
	curfile = stringcopy((*cf)->path, 0);
	if (!curfile) {
	    debug(DBG_ERR, "malloc failed");
	    goto exit;
	}
	dir = dirname(curfile);
	path = malloc(strlen(dir) + strlen(cfgpath) + 2);
	if (!path) {
	    debug(DBG_ERR, "malloc failed");
	    goto exit;
	}
	strcpy(path, dir);
	path[strlen(dir)] = '/';
	strcpy(path + strlen(dir) + 1, cfgpath);
    }
    memset(&globbuf, 0, sizeof(glob_t));
    if (glob(path, 0, NULL, &globbuf)) {
	debug(DBG_WARN, "could not glob %s", path);
	goto exit;
    }

    for (i = globbuf.gl_pathc - 1; i >= 0; i--) {
	f = pushgconfpath(cf, globbuf.gl_pathv[i]);
	if (!f)
	    break;
    }
    globfree(&globbuf);

exit:
    if (curfile) {
	free(curfile);
	free(path);
    }
    return f;
}

int popgconf(struct gconffile **cf) {
    int i;

    if (!*cf)
	return 0;
    for (i = 0; (*cf)[i].data || (*cf)[i].path; i++);
    if (i && (*cf)[0].file) {
	fclose((*cf)[0].file);
	if ((*cf)[0].path) {
	    debug(DBG_DBG, "closing config file %s", (*cf)[0].path);
	    free((*cf)[0].path);
	}
    }
    if (i < 2) {
	free(*cf);
	*cf = NULL;
	return 0;
    }
    memmove(*cf, *cf + 1, sizeof(struct gconffile) * i);
    return 1;
}

void freegconfmstr(char **mstr) {
    int i;

    if (mstr) {
	for (i = 0; mstr[i]; i++)
	    free(mstr[i]);
	free(mstr);
    }
}

void freegconf(struct gconffile **cf) {
    int i;

    if (!*cf)
	return;

    for (i = 0; (*cf)[i].data || (*cf)[i].path; i++) {
	if ((*cf)[i].file) {
	    fclose((*cf)[i].file);
	    if ((*cf)[i].path) {
		debug(DBG_DBG, "closing config file %s", (*cf)[i].path);
		free((*cf)[i].path);
	    }
	}
    }
    free(*cf);
    *cf = NULL;
}

struct gconffile *openconfigfile(const char *file) {
    struct gconffile *cf = NULL;

    if (!pushgconfpath(&cf, file)) {
	debug(DBG_ERR, "could not read config file %s\n%s", file, strerror(errno));
	return NULL;
    }
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

int getlinefromcf(struct gconffile *cf, char *line, const size_t size) {
    size_t i, pos;

    if (!cf)
	return 0;

    if (cf->file)
	return fgets(line, size, cf->file) ? 1 : 0;
    else if (cf->data) {
	pos = cf->datapos;
	if (!cf->data[pos])
	    return 0;
	for (i = pos; cf->data[i] && cf->data[i] != '\n'; i++);
	if (cf->data[i] == '\n')
	    i++;
	if (i - pos > size - 1)
	    i = size - 1 + pos;
	memcpy(line, cf->data + pos, i - pos);
	line[i - pos] = '\0';
	cf->datapos = i;
	return 1;
    }
    return 0;
}

int getconfigline(struct gconffile **cf, char *block, char **opt, char **val, int *conftype) {
    char line[1024];
    char *tokens[3], *s;
    int tcount;

    *opt = NULL;
    *val = NULL;
    *conftype = 0;

    if (!cf || !*cf || (!(*cf)->file && !(*cf)->data))
	return 1;

    for (;;) {
	if (!getlinefromcf(*cf, line, 1024)) {
	    if (popgconf(cf))
		continue;
	    return 1;
	}
	s = line;
	for (tcount = 0; tcount < 3; tcount++) {
	    s = strtokenquote(s, &tokens[tcount], " \t\r\n", "\"'", tcount ? NULL : "#");
	    if (!s) {
		debug(DBG_ERR, "Syntax error in line starting with: %s", line);
		return 0;
	    }
	    if (!tokens[tcount])
		break;
	}
	if (!tcount || **tokens == '#')
	    continue;

	if (**tokens == '}') {
	    if (block)
		return 1;
	    debug(DBG_ERR, "configuration error, found } with no matching {");
	    return 0;
	}
	break;
    }

    switch (tcount) {
    case 2:
	*opt = stringcopy(tokens[0], 0);
	if (!*opt)
	    goto errmalloc;
	*val = stringcopy(tokens[1], 0);
	if (!*val)
	    goto errmalloc;
	*conftype = CONF_STR;
	break;
    case 3:
	if (tokens[1][0] == '=' && tokens[1][1] == '\0') {
	    *opt = stringcopy(tokens[0], 0);
	    if (!*opt)
		goto errmalloc;
	    *val = stringcopy(tokens[2], 0);
	    if (!*val)
		goto errmalloc;
	    *conftype = CONF_STR;
	    break;
	}
	if (tokens[2][0] == '{' && tokens[2][1] == '\0') {
	    *opt = stringcopy(tokens[0], 0);
	    if (!*opt)
		goto errmalloc;
	    *val = stringcopy(tokens[1], 0);
	    if (!*val)
		goto errmalloc;
	    *conftype = CONF_CBK;
	    break;
	}
	/* fall through */
    default:
	if (block)
	    debug(DBG_ERR, "configuration error in block %s, line starting with %s", block, tokens[0]);
	else
	    debug(DBG_ERR, "configuration error, syntax error in line starting with %s", tokens[0]);
	return 0;
    }

    if (**val)
	return 1;

    debug(DBG_ERR, "configuration error, option %s needs a non-empty value", *opt);
    goto errexit;

errmalloc:
    debug(DBG_ERR, "malloc failed");
errexit:
    free(*opt);
    *opt = NULL;
    free(*val);
    *val = NULL;
    return 0;
}

uint8_t hexdigit2int(char d) {
    if (d >= '0' && d <= '9')
	return d - '0';
    if (d >= 'a' && d <= 'f')
	return 10 + d - 'a';
    if (d >= 'A' && d <= 'F')
	return 10 + d - 'A';
    return 0;
}

void unhex(char *s) {
    char *t;
    for (t = s; *t; s++) {
	if (*t == '%' && isxdigit((int)t[1]) && isxdigit((int)t[2])) {
	    *s = 16 * hexdigit2int(t[1]) + hexdigit2int(t[2]);
	    t += 3;
	} else
	    *s = *t++;
    }
    *s = '\0';
}

typedef int (*t_fptr)(struct gconffile **, void *, char *, char *, char *);

/* returns 1 if ok, 0 on error */
/* caller must free returned values also on error */
int getgenericconfig(struct gconffile **cf, char *block, ...) {
    va_list ap;
    char *opt = NULL, *val, *word, *optval, **str = NULL, ***mstr = NULL, **newmstr, *endptr;
    uint8_t *bln = NULL;
    long int *lint = NULL;
    int type = 0, conftype = 0, n;
    t_fptr cbk = NULL;
    void *cbkarg = NULL;

    for (;;) {
	free(opt);
	if (!getconfigline(cf, block, &opt, &val, &conftype))
	    return 0;
	if (!opt)
	    return 1;

	if (conftype == CONF_STR && !strcasecmp(opt, "include")) {
	    if (!pushgconfpaths(cf, val)) {
		debug(DBG_ERR, "failed to include config file %s", val);
		goto errexit;
	    }
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
		    goto errparam;
		break;
	    case CONF_MSTR:
		mstr = va_arg(ap, char ***);
		if (!mstr)
		    goto errparam;
		break;
	    case CONF_BLN:
		bln = va_arg(ap, uint8_t *);
		if (!bln)
		    goto errparam;
		break;
	    case CONF_LINT:
		lint = va_arg(ap, long int *);
		if (!lint)
		    goto errparam;
		break;
	    case CONF_CBK:
		cbk = va_arg(ap, t_fptr);
		if (!cbk)
		    goto errparam;
		cbkarg = va_arg(ap, void *);
		break;
	    default:
		goto errparam;
	    }
	    if (!strcasecmp(opt, word))
		break;
	}
	va_end(ap);

	if (!word) {
	    if (block)
		debug(DBG_ERR, "configuration error in block %s, unknown option %s", block, opt);
	    debug(DBG_ERR, "configuration error, unknown option %s", opt);
	    goto errexit;
	}

	if (((type == CONF_STR || type == CONF_MSTR || type == CONF_BLN || type == CONF_LINT) && conftype != CONF_STR) ||
	    (type == CONF_CBK && conftype != CONF_CBK)) {
	    if (block)
		debug(DBG_ERR, "configuration error in block %s, wrong syntax for option %s", block, opt);
	    debug(DBG_ERR, "configuration error, wrong syntax for option %s", opt);
	    goto errexit;
	}

	switch (type) {
	case CONF_STR:
	    if (*str) {
		debug(DBG_ERR, "configuration error, option %s already set to %s", opt, *str);
		goto errexit;
	    }
	    unhex(val);
	    *str = val;
	    break;
	case CONF_MSTR:
	    if (*mstr)
		for (n = 0; (*mstr)[n]; n++);
	    else
		n = 0;
	    newmstr = realloc(*mstr, sizeof(char *) * (n + 2));
	    if (!newmstr) {
		debug(DBG_ERR, "malloc failed");
		goto errexit;
	    }
	    unhex(val);
	    newmstr[n] = val;
	    newmstr[n + 1] = NULL;
	    *mstr = newmstr;
	    break;
	case CONF_BLN:
	    if (!strcasecmp(val, "on"))
		*bln = 1;
	    else if (!strcasecmp(val, "off"))
		*bln = 0;
	    else {
		if (block)
		    debug(DBG_ERR, "configuration error in block %s, value for option %s must be on or off, not %s", block, opt, val);
		else
		    debug(DBG_ERR, "configuration error, value for option %s must be on or off, not %s", opt, val);
		goto errexit;
	    }
	    break;
	case CONF_LINT:
	    endptr = NULL;
	    *lint = strtol(val, &endptr, 0);
	    if (*lint == LONG_MIN || *lint == LONG_MAX || !endptr || endptr == val || *endptr != '\0') {
		if (block)
		    debug(DBG_ERR, "configuration error in block %s, value for option %s must be an integer, not %s", block, opt, val);
		else
		    debug(DBG_ERR, "configuration error, value for option %s must be an integer, not %s", opt, val);
		goto errexit;
	    }
	    break;
	case CONF_CBK:
	    optval = malloc(strlen(opt) + strlen(val) + 2);
	    if (!optval) {
		debug(DBG_ERR, "malloc failed");
		goto errexit;
	    }
	    sprintf(optval, "%s %s", opt, val);
	    if (!cbk(cf, cbkarg, optval, opt, val)) {
		free(optval);
		goto errexit;
	    }
	    free(val);
	    free(optval);
	    continue;
	default:
	    goto errparam;
	}
	if (block)
	    debug(DBG_DBG, "getgenericconfig: block %s: %s = %s", block, opt, val);
	else
	    debug(DBG_DBG, "getgenericconfig: %s = %s", opt, val);
	if (type == CONF_BLN || type == CONF_LINT)
	    free(val);
    }

errparam:
    debug(DBG_ERR, "getgenericconfig: internal parameter error");
errexit:
    free(opt);
    free(val);
    return 0;
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
