CFLAGS = -Wall -g

all: blocking.o

blocking.o: blocking.c blocking.h ../libradsec-base.h ../libradsec.h
	$(CC) $(CFLAGS) -c -I .. $^

clean:
	-rm *.o
