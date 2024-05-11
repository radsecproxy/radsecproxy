/* Copyright (c) 2007-2008, UNINETT AS */
/* See LICENSE for licensing information. */

#define CONF_STR 1
#define CONF_CBK 2
#define CONF_MSTR 3
#define CONF_BLN 4
#define CONF_LINT 5
#define CONF_STR_NOESC 6
#define CONF_MSTR_NOESC 7

#include <stdio.h>
#include <stdint.h>

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
int unhex(char *s, uint8_t process_null);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
