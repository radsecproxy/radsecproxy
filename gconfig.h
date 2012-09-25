/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#define CONF_STR 1
#define CONF_CBK 2
#define CONF_MSTR 3
#define CONF_BLN 4
#define CONF_LINT 5

#include <stdio.h>

struct gconffile {
    char *path;
    FILE *file;
    const char *data;
    size_t datapos;
};

int getconfigline(struct gconffile **cf, char *block, char **opt, char **val, int *conftype);
int getgenericconfig(struct gconffile **cf, char *block, ...);
int pushgconfdata(struct gconffile **cf, const char *data);
FILE *pushgconfpath(struct gconffile **cf, const char *path);
FILE *pushgconffile(struct gconffile **cf, FILE *file, const char *description);
FILE *pushgconfpaths(struct gconffile **cf, const char *path);
int popgconf(struct gconffile **cf);
void freegconfmstr(char **mstr);
void freegconf(struct gconffile **cf);
struct gconffile *openconfigfile(const char *file);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
