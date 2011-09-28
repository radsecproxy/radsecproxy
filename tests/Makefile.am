check_PROGRAMS =

if WANT_FTICKS
check_PROGRAMS += t_fticks
endif

AM_CFLAGS = -g -Wall -Werror @TARGET_CFLAGS@
AM_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
LDADD = $(top_builddir)/librsp.a @SSL_LIBS@

TESTS = $(check_PROGRAMS)
