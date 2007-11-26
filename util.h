#include <sys/socket.h>

char *stringcopy(const char *s, int len);
char *addr2string(struct sockaddr *addr, socklen_t len);
void printfchars(char *prefixfmt, char *prefix, char *charfmt, char *chars, int len);
int connectport(int type, char *host, char *port);
