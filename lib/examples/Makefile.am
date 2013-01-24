AUTOMAKE_OPTIONS = foreign
INCLUDES = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -Werror -g

noinst_PROGRAMS = client client2

client_SOURCES = client-blocking.c
client_LDADD = ../libradsec.la #-lefence
client_CFLAGS = $(AM_CFLAGS) -DUSE_CONFIG_FILE

client2_SOURCES = client-dispatch.c
client2_LDADD = ../libradsec.la #-lefence
client2_CFLAGS = $(AM_CFLAGS) -DUSE_CONFIG_FILE
