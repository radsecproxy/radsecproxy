AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . examples include 

INCLUDES = -I$(srcdir)/include
AM_CFLAGS = -Wall -g

lib_LTLIBRARIES = libradsec.la

libradsec_la_SOURCES = \
	attr.c \
	conf.c \
	conn.c \
	debug.c \
	err.c \
	packet.c \
	peer.c \
	radsec.c \
	request.c

libradsec_la_SOURCES += \
	rsp_debug.c \
	rsp_hash.c \
	rsp_list.c \
	rsp_util.c

if RS_ENABLE_TLS
libradsec_la_SOURCES += \
	tls.c \
	rsp_tlscommon.c
endif

libradsec_la_LDFLAGS = -version-info 0:0:0
libradsec_la_CFLAGS = $(AM_CFLAGS) #-DDEBUG -DDEBUG_LEVENT -Werror
