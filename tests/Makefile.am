AUTOMAKE_OPTIONS = foreign

check_PROGRAMS = t_fticks
AM_CFLAGS = -g -Wall -Werror @TARGET_CFLAGS@
LDADD = $(top_builddir)/librsp.a @SSL_LIBS@

TESTS = $(check_PROGRAMS)
