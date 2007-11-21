CFLAGS = -g -Wall -pedantic -pthread
LDFLAGS = -lssl
OBJ = util.o debug.o list.o gconfig.o radsecproxy.o

all: radsecproxy

radsecproxy: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o radsecproxy
clean:
	rm -f $(OBJ) radsecproxy
