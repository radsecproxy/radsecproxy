AUTOMAKE_OPTIONS = foreign
INCLUDES = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -g

bin_PROGRAMS = client
client_SOURCES = client-blocking.c
client_LDADD = ../libradsec.la
client_CFLAGS = $(AM_CFLAGS) -DUSE_CONFIG_FILE
