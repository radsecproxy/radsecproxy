#include <sys/socket.h>
#include <netdb.h>

char *stringcopy(const char *s, int len);
char *addr2string(struct sockaddr *addr, socklen_t len);
int addr_equal(struct sockaddr *a, struct sockaddr *b);
struct sockaddr *addr_copy(struct sockaddr *in);
uint16_t port_get(struct sockaddr *sa);
void port_set(struct sockaddr *sa, uint16_t port);

void printfchars(char *prefixfmt, char *prefix, char *charfmt, char *chars, int len);
int connectport(int type, char *host, char *port);
