AUTOMAKE_OPTIONS = foreign

SUBDIRS = tests

sbin_PROGRAMS = radsecproxy
bin_PROGRAMS = radsecproxy-conf
noinst_LIBRARIES = librsp.a

radsecproxy_SOURCES = main.c

librsp_a_SOURCES = \
	debug.c debug.h \
	dtls.c dtls.h \
	gconfig.c gconfig.h \
	hash.c hash.h \
	hostport.c hostport.h \
	list.c list.h \
	radmsg.c radmsg.h \
	radsecproxy.c radsecproxy.h \
	tcp.c tcp.h \
	tls.c tls.h \
	tlscommon.c tlscommon.h \
	tlv11.c tlv11.h \
	udp.c udp.h \
	util.c util.h

if WANT_FTICKS
librsp_a_SOURCES += fticks.c fticks.h
endif

radsecproxy_conf_SOURCES = \
	catgconf.c \
	debug.c debug.h \
	gconfig.c gconfig.h \
	util.c util.h

librsp_a_CFLAGS = \
	-g -Wall -Werror -fno-strict-aliasing @SSL_CFLAGS@ @TARGET_CFLAGS@
radsecproxy_CFLAGS = $(librsp_a_CFLAGS)
radsecproxy_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
radsecproxy_LDADD = librsp.a @SSL_LIBS@

radsecproxy_conf_CFLAGS = -g -Wall -fno-strict-aliasing @TARGET_CFLAGS@
radsecproxy_conf_LDFLAGS = @TARGET_LDFLAGS@

dist_man_MANS = radsecproxy.1 $(GENMANPAGES)

EXTRA_DIST = \
	configure Makefile.in tests/Makefile.in \
	compile config.guess config.sub install-sh missing depcomp
EXTRA_DIST += \
	LICENSE THANKS \
	radsecproxy.conf.5.xml radsecproxy.conf-example \
	tools/README tools/naptr-eduroam.sh tools/radsec-dynsrv.sh

if HAVE_DOCBOOK2X_MAN
GENMANPAGES = radsecproxy.conf.5
endif

radsecproxy.conf.5: $(srcdir)/radsecproxy.conf.5.xml
	docbook2x-man $<

# Build HTML version of radsecproxy.conf.5.  NOTE: Only tested with
# 'openjade' package installed on Ubuntu 9.10.
html: $(srcdir)/radsecproxy.conf.5.xml
	-openjade -E2000 -t sgml-raw -d /usr/share/sgml/docbook/stylesheet/dsssl/modular/html/docbook.dsl -o radsecproxy.conf.html $<

clean-local:
	-rm radsecproxy.conf.5
