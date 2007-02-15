CFLAGS = -g -Wall -pedantic -pthread
LDFLAGS = -lssl
OBJ = util.o radsecproxy.o

all: radsecproxy

radsecproxy: $(OBJ) radsecproxy.o
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o radsecproxy
clean:
	rm -f $(OBJ) radsecproxy
