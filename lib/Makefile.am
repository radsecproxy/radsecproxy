AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . examples include 

INCLUDES = -I$(srcdir)/include

lib_LTLIBRARIES = libradsec.la
libradsec_la_SOURCES = \
	attr.c \
	conf.c \
	debug.c \
	err.c \
	packet.c \
	request.c \
	radsec.c
libradsec_la_LDFLAGS = -version-info 0:0:0
libradsec_la_CFLAGS = $(CFLAGS) -DDEBUG -DDEBUG_LEVENT
