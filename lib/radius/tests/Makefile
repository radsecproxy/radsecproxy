#
#  GNU Makefile
#
.PHONY: all clean
all: radattr

HEADERS		:= ../client.h ../radius.h
CFLAGS		:= -g

%.o : %.c
	$(CC) $(CFLAGS) -I.. -I. -c $<

%.o: ${HEADERS}

LIBS	:= -lcrypto -lssl
LDFLAGS = -L.. -lnetworkradius-client

../libnetworkradius-client.a:
	@${MAKE} -C .. libnetworkradius-client.a

radattr: radattr.o ../libnetworkradius-client.a
	${CC} ${LFDLAGS} ${LIBS} -o $@ $^

clean:
	@rm -rf *.o *.a *~
