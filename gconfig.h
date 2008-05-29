#define CONF_STR 1
#define CONF_CBK 2
#define CONF_MSTR 3
#define CONF_BLN 4

struct gconffile {
    char *path;
    FILE *file;
    const char *data;
    size_t datapos;
};

int getconfigline(struct gconffile **cf, char *block, char **opt, char **val, int *conftype);
int getgenericconfig(struct gconffile **cf, char *block, ...);
int pushgconfdata(struct gconffile **cf, const char *data);
FILE *pushgconffile(struct gconffile **cf, const char *path);
FILE *pushgconffiles(struct gconffile **cf, const char *path);
int popgconf(struct gconffile **cf);
void freegconf(struct gconffile **cf);
struct gconffile *openconfigfile(const char *file);
