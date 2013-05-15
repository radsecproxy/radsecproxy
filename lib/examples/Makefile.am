AUTOMAKE_OPTIONS = foreign
INCLUDES = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -Werror -g -DDEBUG -DDEBUG_LEVENT

LDADD = ../libradsec.la #-lefence
CFLAGS = $(AM_CFLAGS) -DUSE_CONFIG_FILE

noinst_PROGRAMS = client client2 server
client_SOURCES = client-blocking.c
client2_SOURCES = client-dispatch.c
