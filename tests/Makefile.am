AUTOMAKE_OPTIONS = foreign

check_PROGRAMS = t_fticks
AM_CFLAGS = -g -Wall -Werror @SSL_CFLAGS@ @TARGET_CFLAGS@
LDADD = $(top_builddir)/librsp.a @SSL_LIBS@
LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@

TESTS = $(check_PROGRAMS)
