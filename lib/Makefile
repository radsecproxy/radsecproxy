CFLAGS = -Wall -g -I include -DDEBUG

OFILES = attr.o \
	conf.o \
	debug.o \
	err.o \
	packet.o \
	request.o \
	radsec.o

all: libradsec.a

libradsec.a: $(OFILES)
	ar rc $@ $^

$(OFILES): include/radsec/radsec.h include/radsec/radsec-impl.h

doc:
	doxygen

clean:
	-rm *.o *.a *.gch

