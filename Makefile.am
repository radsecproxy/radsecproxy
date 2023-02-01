## Copyright (c) 2006-2010, UNINETT AS
## Copyright (c) 2010-2012,2016, NORDUnet A/S
## See LICENSE for licensing information.

AUTOMAKE_OPTIONS = foreign

SUBDIRS = tests

sbin_PROGRAMS = radsecproxy
bin_PROGRAMS = radsecproxy-conf radsecproxy-hash
noinst_LIBRARIES = librsp.a

radsecproxy_SOURCES = main.c

librsp_a_SOURCES = \
	debug.c debug.h \
	dns.c dns.h \
	dtls.c dtls.h \
	fticks.c fticks.h fticks_hashmac.c fticks_hashmac.h \
	gconfig.c gconfig.h \
	hash.c hash.h \
	hostport.c hostport.h \
	list.c list.h \
	radmsg.c radmsg.h raddict.h \
	radsecproxy.c radsecproxy.h \
	rewrite.c rewrite.h \
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
	-g -Wall -Werror -fno-strict-aliasing @OPENSSL_INCLUDES@ @TARGET_CFLAGS@

radsecproxy_LDFLAGS = @OPENSSL_LDFLAGS@ @TARGET_LDFLAGS@
radsecproxy_LDADD = librsp.a @OPENSSL_LIBS@ @LIBS@
radsecproxy_conf_LDFLAGS = @TARGET_LDFLAGS@
radsecproxy_hash_LDADD = fticks_hashmac.o hash.o list.o

man_MANS = radsecproxy.8 radsecproxy-hash.8 radsecproxy.conf.5

EXTRA_DIST = \
	LICENSE THANKS \
	radsecproxy.conf-example \
	tools/README tools/naptr-eduroam.sh tools/radsec-dynsrv.sh

distclean-local:
	rm -f @PACKAGE@-*.tar.gz

####################

html: radsecproxy.html radsecproxy-hash.html radsecproxy.conf.html

%.html: %.8
	groff -mandoc -Thtml $< >$@
%.html: %.5
	groff -mandoc -Thtml $< >$@
