SPECIAL = 
#SPECIAL += -DUSE_REQUEST_OBJECT
SPECIAL += -DUSE_CONFIG_FILE

CFLAGS = -Wall -g -I ../include $(SPECIAL)

HFILES = ../include/radsec/radsec.h ../include/radsec/radsec-impl.h

all: client-blocking

client-blocking: client-blocking.c ../libradsec.a $(HFILES)
	$(CC) $(CFLAGS) -o $@ $< -lconfuse -L /usr/lib/freeradius -lfreeradius-radius -L .. -lradsec -L /usr/local/lib -levent_core

clean:
	-rm *.o *.gch client-blocking
