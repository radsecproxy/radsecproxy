AUTOMAKE_OPTIONS = foreign

check_PROGRAMS = t_fticks t_rewrite
AM_CFLAGS = -g -Wall -Werror @SSL_CFLAGS@ @TARGET_CFLAGS@
LDADD = $(top_builddir)/librsp.a @SSL_LIBS@

TESTS = $(check_PROGRAMS)
