CFLAGS = -g -Wall -pthread
LDFLAGS = -lssl
OBJ = util.o

all: radsecproxy

radsecproxy: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o radsecproxy radsecproxy.c
clean:
	rm -f $(OBJ) radsecproxy
