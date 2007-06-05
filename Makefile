CFLAGS = -Wall -pedantic -pthread
LDFLAGS = -lssl
OBJ = util.o debug.o radsecproxy.o

all: radsecproxy

radsecproxy: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o radsecproxy
clean:
	rm -f $(OBJ) radsecproxy
