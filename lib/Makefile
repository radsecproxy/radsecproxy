CFLAGS = -Wall -g -DDEBUG
OFILES = radsec.o err.o packet.o attr.o

all: libradsec.a

base.o: base.c libradsec-base.h libradsec.h ../tlv11.h

libradsec.a: $(OFILES)
	ar rc $@ $^

doc:
	doxygen

clean:
	-rm *.o *.a
