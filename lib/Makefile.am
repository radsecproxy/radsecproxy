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

VER_CUR = 1
VER_REV = 0
VER_AGE = 0

SUBDIRS = radius radsecproxy include . examples
DIST_SUBDIRS = $(SUBDIRS) tests

INCLUDES = -I$(srcdir)/include
AM_CFLAGS = -Wall -Werror -g

lib_LTLIBRARIES = libradsec.la

libradsec_la_SOURCES = \
	avp.c \
	compat.c \
	conf.c \
	confutil.c \
	conn.c \
	debug.c \
	err.c \
	event.c \
	listener.c \
	message.c \
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
	peer.h \
	radsec.h \
	tcp.h \
	tls.h \
	udp.h \
	util.h

EXTRA_DIST = HACKING LICENSE radsec.sym
EXTRA_libradsec_la_DEPENDENCIES = radsec.sym

libradsec_la_CFLAGS = \
	$(AM_CFLAGS) -DHAVE_CONFIG_H #-DDEBUG -DDEBUG_LEVENT
libradsec_la_LDFLAGS = \
	-version-info $(VER_CUR):$(VER_REV):$(VER_AGE) \
	-export-symbols $(srcdir)/radsec.sym
libradsec_la_LIBADD = \
	radsecproxy/libradsec-radsecproxy.la \
	radius/libradsec-radius.la
