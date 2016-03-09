AUTOMAKE_OPTIONS = foreign

if WANT_FTICKS
fticks_sources = fticks.c fticks.h fticks_hashmac.c fticks_hashmac.h
fticks_programs = radsecproxy-hash
radsecproxy_hash_LDADD = fticks_hashmac.o hash.o list.o
endif

if HAVE_DOCBOOK2X_MAN
GENMANPAGES = radsecproxy.conf.5
endif

SUBDIRS = tests

sbin_PROGRAMS = radsecproxy
bin_PROGRAMS = radsecproxy-conf $(fticks_programs)
noinst_LIBRARIES = librsp.a

radsecproxy_SOURCES = main.c

librsp_a_SOURCES = \
	$(fticks_sources) \
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

radsecproxy_conf_SOURCES = \
	catgconf.c \
	debug.c debug.h \
	gconfig.c gconfig.h \
	util.c util.h

####################
AM_CPPFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\"
AM_CFLAGS = \
	-g -Wall -Werror -fno-strict-aliasing @SSL_CFLAGS@ @TARGET_CFLAGS@

radsecproxy_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
radsecproxy_LDADD = librsp.a @SSL_LIBS@

radsecproxy_conf_LDFLAGS = @TARGET_LDFLAGS@

dist_man_MANS = radsecproxy.1 radsecproxy-hash.1 radsecproxy.conf.5

EXTRA_DIST = \
	LICENSE THANKS \
	configure Makefile.in tests/Makefile.in \
	compile config.guess config.sub install-sh missing depcomp \
	radsecproxy.conf.5.xml radsecproxy.conf-example \
	tools/README tools/naptr-eduroam.sh tools/radsec-dynsrv.sh

DISTCHECK_CONFIGURE_FLAGS = --enable-fticks

####################
radsecproxy.conf.5: $(srcdir)/radsecproxy.conf.5.xml
	docbook2x-man $<

html: radsecproxy.html radsecproxy-hash.html radsecproxy.conf.html

%.html: %.1
	groff -mandoc -Thtml $< >$@
%.html: %.5
	groff -mandoc -Thtml $< >$@

clean-local:
	-rm $(GENMANPAGES)
