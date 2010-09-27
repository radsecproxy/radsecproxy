CFLAGS = -Wall -g

all: blocking.o

blocking.o: blocking.c blocking.h ../libradsec-base.h ../libradsec.h
	$(CC) $(CFLAGS) -c -I .. $^

client: client.c ../libradsec.a ../libradsec.h ../libradsec-impl.h
	$(CC) $(CFLAGS) -o $@ -L /usr/lib/freeradius -lfreeradius-radius $^

clean:
	-rm *.o
