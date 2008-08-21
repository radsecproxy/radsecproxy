CFLAGS = -g -Wall -pedantic -pthread
LDFLAGS = -lssl
OBJ = util.o debug.o list.o gconfig.o tcp.o dtls.o radsecproxy.o

all: radsecproxy

radsecproxy: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o radsecproxy

catgconf: util.o debug.o gconfig.o catgconf.o
	$(CC) $(CFLAGS) util.o debug.o gconfig.o catgconf.o -o catgconf

clean:
	rm -f $(OBJ) catgconf.o radsecproxy catgconf
