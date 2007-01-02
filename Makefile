CFLAGS = -g -Wall -pthread
LDFLAGS = -lssl

all: radsecproxy

radsecproxy: util.o

clean:
	rm -f util.o radsecproxy
