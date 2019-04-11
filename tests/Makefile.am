AUTOMAKE_OPTIONS = foreign

#LOG_DRIVER = ./tap-driver.sh
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
                  $(top_srcdir)/build-aux/tap-driver.sh

check_PROGRAMS = t_fticks t_rewrite t_resizeattr t_rewrite_config
AM_CFLAGS = -g -Wall -Werror @SSL_CFLAGS@ @TARGET_CFLAGS@
LDADD = $(top_builddir)/librsp.a @SSL_LIBS@

TESTS = $(check_PROGRAMS)
