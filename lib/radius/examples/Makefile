#
#  GNU Makefile
#
.PHONY: all clean install

SRCS = example_1.c example_2.c example_3.c example_4.c

OBJS 	 := ${SRCS:.c=.o}
PROGRAMS := ${SRCS:.c=}

all: ${PROGRAMS}

HEADERS		:= ../client.h ../radius.h

${OBJS}: ${HEADERS}

$(info ${PROGRAMS} ${OBJS})

${PROGRAMS}: ../libnetworkradius-client.a


%.o : %.c
	$(CC) $(CFLAGS) -I.. -I. -c $<

%.o: ${HEADERS}

LDFLAGS = -L.. -lnetworkradius-client -lcrypto -lssl
CFLAGS  = -I..

../libnetworkradius-client.a:
	@${MAKE} -C .. libnetworkradius-client.a

radsample.o: radsample.c ${HEADERS} nr_vp_create.c nr_packet_send.c

#radsample: radsample.o ../libnetworkradius-client.a
#	${CC} ${LFDLAGS} ${LIBS} -o $@ $^

sample_chap.o: sample_chap.c ${HEADERS}

sample_chap: sample_chap.o ../libnetworkradius-client.a
	${CC} ${LFDLAGS} ${LIBS} -o $@ $^

radsample2.o: radsample2.c ${HEADERS} nr_vp_create.c

radsample2: radsample2.o ../libnetworkradius-client.a
	${CC} ${LFDLAGS} ${LIBS} -o $@ $^

radsample3.o: radsample3.c ${HEADERS} nr_transmit.c nr_server_t.c nr_vp_create.c

radsample3: radsample3.o ../libnetworkradius-client.a
	${CC} ${LFDLAGS} ${LIBS} -o $@ $^

clean:
	@rm -rf *.o *.a *~
