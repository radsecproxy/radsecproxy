AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)
AM_CFLAGS = -Wall -g

noinst_LTLIBRARIES = libradsec-radsecproxy.la

libradsec_radsecproxy_la_SOURCES = \
	debug.c \
	hash.c \
	list.c \
	util.c

if RS_ENABLE_TLS
libradsec_radsecproxy_la_SOURCES += \
	tlscommon.c
endif
