CFLAGS = -Wall -g

all: blocking.o

blocking.o: blocking.c blocking.h ../libradsec-base.h ../libradsec.h
	$(CC) $(CFLAGS) -c -I .. $^

client: client.c ../radsec.o ../libradsec.h ../debug.h
	$(CC) $(CFLAGS) -o $@ -L /usr/lib/freeradius -lfreeradius-radius $^

clean:
	-rm *.o
