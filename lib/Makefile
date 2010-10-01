CFLAGS = -Wall -g -DDEBUG

OFILES = attr.o \
	debug.o \
	err.o \
	packet.o \
	radsec.o

all: libradsec.a

libradsec.a: $(OFILES)
	ar rc $@ $^

$(OFILES): libradsec.h libradsec-impl.h

doc:
	doxygen

clean:
	-rm *.o *.a *.gch

