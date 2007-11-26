#define CONF_STR 1
#define CONF_CBK 2
#define CONF_MSTR 3

struct gconffile {
    char *path;
    FILE *file;
};

void getgenericconfig(FILE *f, char *block, ...);
FILE *pushgconffile(struct gconffile **cf, const char *path);
FILE *popgconffile(struct gconffile **cf);
