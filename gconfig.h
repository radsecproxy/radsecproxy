#define CONF_STR 1
#define CONF_CBK 2
#define CONF_MSTR 3
#define CONF_BLN 4

struct gconffile {
    char *path;
    FILE *file;
};

int getconfigline(struct gconffile **cf, char *block, char **opt, char **val, int *conftype);
int getgenericconfig(struct gconffile **cf, char *block, ...);
FILE *pushgconffile(struct gconffile **cf, const char *path);
FILE *pushgconffiles(struct gconffile **cf, const char *path);
FILE *popgconffile(struct gconffile **cf);
struct gconffile *openconfigfile(const char *file);
