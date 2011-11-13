#
#  GNU Makefile
#
.PHONY: all clean install
all: libnetworkradius-client.a

SRCS		:= dict.c attrs.c packet.c valuepair.c static.c id.c \
		   crypto.c custom.c print.c parse.c

OBJS		:= ${SRCS:.c=.o}

HEADERS		:= client.h radius.h

CFLAGS		:= -I. -g -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -W -Wredundant-decls -Wundef

VERSION := 1.0
NAME := networkradius-client-$(VERSION)


#
#  The DICTIONARIES variable can be used to point to the FreeRADIUS
#  dictionaries.
#
ifeq "${DICTIONARIES}" ""
DICTIONARIES	:= $(filter-out %~,$(wildcard share/dictionary*))
endif

${OBJS}: ${HEADERS}

radius.h dictionaries.c: ${DICTIONARIES} convert.pl common.pl
	./convert.pl ${DICTIONARIES}

static.o: static.c dictionaries.c

%.o : %.c
	$(CC) $(CFLAGS) -c $<

%.o: ${HEADERS}

.PHONY: networkradius-devel
networkradius-devel:
	@[ -e $@ ] || ln -s . $@

libnetworkradius-client.a: ${OBJS}
	${AR} ${ARFLAGS} $@ $^

LIBS	:= -lcrypto -lssl
LDFLAGS = -L. -lnetworkradius-client

.PHONY: html
html:
	doxygen doxygen.conf

clean:
	@rm -rf *.o *.a *~ html

install: libnetworkradius-client.a

.PHONY: publish
publish:
	@scp -r html/* networkradius.com@liberty:www.new/site/clientapi/

$(NAME).tar.gz: $(wildcard Makefile *.pl *.txt *.[ch] \
	examples/*.[ch] doc/*.txt share/dictionary*)
	git archive --format=tar --prefix=$(NAME)/ bsd | gzip > $@

.PHONY: tar
tar: $(NAME).tar.gz
