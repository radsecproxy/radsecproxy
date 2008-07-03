#define CONF_STR 1
#define CONF_CBK 2
#define CONF_MSTR 3
#define CONF_BLN 4
#define CONF_LINT 5

struct gconffile {
    char *path;
    FILE *file;
};

void getconfigline(struct gconffile **cf, char *block, char **opt, char **val, int *conftype);
void getgenericconfig(struct gconffile **cf, char *block, ...);
FILE *pushgconffile(struct gconffile **cf, const char *path);
FILE *pushgconffiles(struct gconffile **cf, const char *path);
FILE *popgconffile(struct gconffile **cf);
struct gconffile *openconfigfile(const char *file);
