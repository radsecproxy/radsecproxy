AUTOMAKE_OPTIONS = foreign
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)
AM_CFLAGS = -Wall -Werror -g

noinst_PROGRAMS = client
client_SOURCES = client-blocking.c
client_LDADD = ../libradsec.la #-lefence
client_CFLAGS = $(AM_CFLAGS) -DUSE_CONFIG_FILE
