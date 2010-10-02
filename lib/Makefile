CFLAGS = -Wall -g -I include -DDEBUG

OFILES = attr.o \
	debug.o \
	err.o \
	packet.o \
	radsec.o

all: libradsec.a

libradsec.a: $(OFILES)
	ar rc $@ $^

$(OFILES): include/radsec/libradsec.h include/radsec/libradsec-impl.h

doc:
	doxygen

clean:
	-rm *.o *.a *.gch

