AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)
AM_CFLAGS = -Wall -Werror -g

noinst_LTLIBRARIES = libradsec-radsecproxy.la

libradsec_radsecproxy_la_SOURCES = \
	debug.c debug.h \
	gconfig.h \
	hash.c hash.h \
	hostport_types.h \
	list.c list.h \
	radmsg.h \
	radsecproxy.h \
	tlv11.h \
	util.c util.h

if RS_ENABLE_TLS
libradsec_radsecproxy_la_SOURCES += \
	tlscommon.c tlscommon.h
endif
