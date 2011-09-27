#include "../radsecproxy.h"
#include "../fticks.h"

int
main (int argc, char *argv[])
{
  uint8_t buf[128];

  fticks_hashmac((const uint8_t *) "xyzzy", NULL, sizeof(buf), buf);
  return 0;
}
