CFLAGS = -Wall -g -I ../include

HFILES = ../include/radsec/libradsec.h ../include/radsec/libradsec-impl.h

all: client-blocking

client-blocking: client-blocking.c ../libradsec.a $(HFILES)
	$(CC) $(CFLAGS) -o $@ $< -L /usr/lib/freeradius -lfreeradius-radius -L .. -lradsec -L /usr/local/lib -levent_core

clean:
	-rm *.o client-blocking *.gch
