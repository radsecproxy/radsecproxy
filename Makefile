CFLAGS = -g -Wall -pedantic -pthread -DRADPROT_UDP -DRADPROT_TCP -DRADPROT_TLS -DRADPROT_DTLS
LDFLAGS = -lssl
OBJ = util.o debug.o list.o hash.o gconfig.o tlv11.o radmsg.o udp.o tcp.o tls.o dtls.o radsecproxy.o

all: radsecproxy

radsecproxy: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o radsecproxy

catgconf: util.o debug.o gconfig.o catgconf.o
	$(CC) $(CFLAGS) util.o debug.o gconfig.o catgconf.o -o catgconf

clean:
	rm -f $(OBJ) catgconf.o radsecproxy catgconf

man:
	docbook2man.pl --to-stdout radsecproxy.conf.5.xml > radsecproxy.conf.5

html:
	openjade -E10000 -t sgml-raw -d /usr/share/sgml/docbook/dsssl-stylesheets-1.79/html/docbook.dsl -o radsecproxy.conf.5.html radsecproxy.conf.5.xml
