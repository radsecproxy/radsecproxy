AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)
AM_CFLAGS = -Wall -g

noinst_LTLIBRARIES = libradsec-radius.la

libradsec_radius_la_SOURCES = \
	attrs.c \
	crypto.c \
	custom.c \
	dict.c \
	id.c \
	parse.c \
	print.c \
	radpkt.c \
	static.c \
	valuepair.c

libradsec_radius_la_CFLAGS = $(AM_CFLAGS) -DHAVE_CONFIG_H

DICTIONARIES = \
	share/dictionary.txt \
	share/dictionary.juniper \
	share/dictionary.microsoft \
	share/dictionary.ukerna \
	share/dictionary.abfab.ietf

EXTRA_DIST = $(DICTIONARIES)

$(top_srcdir)/include/radsec/radius.h dictionaries.c: ${DICTIONARIES} convert.pl common.pl
	$(srcdir)/convert.pl ${DICTIONARIES}

static.$(OBJEXT): static.c dictionaries.c

clean-local:
	rm -f dictionaries.c

$(libradsec_radius_la_SOURCES): $(top_srcdir)/include/radsec/radius.h

