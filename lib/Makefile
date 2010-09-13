CFLAGS = -Wall -g

all: base.o

base.o: base.c libradsec-base.h libradsec.h ../tlv11.h

doc:
	doxygen

clean:
	-rm *.o
