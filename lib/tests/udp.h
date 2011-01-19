#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
//#include <sys/types.h>

typedef ssize_t (*data_cb) (const uint8_t *buf, ssize_t len);
struct polldata {
  int s;
  data_cb cb;
  struct timeval *timeout;
};

struct polldata *server (const char *bindto, struct timeval *timeout, data_cb cb);
ssize_t poll (struct polldata *data);
