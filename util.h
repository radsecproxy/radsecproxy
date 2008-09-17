#include <sys/socket.h>
#include <netdb.h>

#define SOCKADDR_SIZE(addr) ((addr).ss_family == AF_INET ? \
                            sizeof(struct sockaddr_in) : \
                            sizeof(struct sockaddr_in6))

#define SOCKADDRP_SIZE(addr) ((addr)->sa_family == AF_INET ? \
                            sizeof(struct sockaddr_in) : \
                            sizeof(struct sockaddr_in6))

char *stringcopy(const char *s, int len);
char *addr2string(struct sockaddr *addr);
int addr_equal(struct sockaddr *a, struct sockaddr *b);
struct sockaddr *addr_copy(struct sockaddr *in);
uint16_t port_get(struct sockaddr *sa);
void port_set(struct sockaddr *sa, uint16_t port);

void printfchars(char *prefixfmt, char *prefix, char *charfmt, char *chars, int len);
int connectport(int type, char *host, char *port);
