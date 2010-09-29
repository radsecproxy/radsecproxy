CFLAGS = -Wall -g

all: client

blocking.o: blocking.c blocking.h ../libradsec-base.h ../libradsec.h
	$(CC) $(CFLAGS) -c -I .. $^

client: client.c ../libradsec.a ../libradsec.h ../libradsec-impl.h
	$(CC) $(CFLAGS) -o $@ $< -L /usr/lib/freeradius -lfreeradius-radius -L .. -lradsec -L /usr/local/lib -levent

clean:
	-rm *.o client
