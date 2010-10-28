AUTOMAKE_OPTIONS = foreign

INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = client
client_SOURCES = client-blocking.c
client_LDADD = ../libradsec.la
client_CFLAGS = $(CFLAGS) -DUSE_CONFIG_FILE -DUSE_REQUEST_OBJECT
