AUTOMAKE_OPTIONS = foreign

if WANT_FTICKS
fticks_programs = t_fticks
endif

check_PROGRAMS = $(fticks_programs)
AM_CFLAGS = -g -Wall -Werror @TARGET_CFLAGS@
AM_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
LDADD = $(top_builddir)/librsp.a @SSL_LIBS@

TESTS = $(check_PROGRAMS)
