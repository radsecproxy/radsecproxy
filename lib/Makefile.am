AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

# Shared library interface version, i.e. -version-info to Libtool,
# expressed as three integers CURRENT:REVISION:AGE.
#
# CURRENT is the version number of the current interface. Increment
# CURRENT when the library interface has changed or has been extended.
#
# REVISION is the version number of the _implementation_ of the
# CURRENT interface. Set REVISION to 0 when CURRENT changes, else
# increment.
#
# AGE is the number of interfaces this library implements, i.e. how
# many versions before CURRENT that are supported. Increment AGE when
# the library interface is _extended_. Set AGE to 0 when the library
# interface is _changed_.


SUBDIRS = radius radsecproxy include . examples
DIST_SUBDIRS = $(SUBDIRS) tests

INCLUDES = -I$(srcdir)/include
AM_CFLAGS = -Wall -Werror -g

lib_LTLIBRARIES = libradsec.la

libradsec_la_SOURCES = \
	avp.c \
	compat.c \
	conf.c \
	conn.c \
	debug.c \
	err.c \
	event.c \
	packet.c \
	peer.c \
	radsec.c \
	request.c \
	send.c \
	tcp.c \
	udp.c \
	util.c

if RS_ENABLE_TLS
libradsec_la_SOURCES += tls.c
else
libradsec_la_SOURCES += md5.c
endif

libradsec_la_SOURCES += \
	compat.h \
	conn.h \
	debug.h \
	err.h \
	event.h \
	md5.h \
	packet.h \
	peer.h \
	radsec.h \
	tcp.h \
	tls.h \
	udp.h \
	util.h

EXTRA_DIST = HACKING LICENSE libradsec.spec radsec.sym
EXTRA_libradsec_la_DEPENDENCIES = radsec.sym
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-tls --enable-tls-psk

libradsec_la_LIBADD = radsecproxy/libradsec-radsecproxy.la radius/libradsec-radius.la
libradsec_la_LDFLAGS = -version-info 1:0:1 -export-symbols $(srcdir)/radsec.sym
libradsec_la_CFLAGS = $(AM_CFLAGS) -DHAVE_CONFIG_H -Werror # -DDEBUG -DDEBUG_LEVENT 
