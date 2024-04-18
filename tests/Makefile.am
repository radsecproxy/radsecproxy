AUTOMAKE_OPTIONS = foreign

#LOG_DRIVER = ./tap-driver.sh
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
                  $(top_srcdir)/build-aux/tap-driver.sh

check_PROGRAMS = \
    t_fticks \
    t_rewrite \
    t_resizeattr \
    t_rewrite_config \
    t_verify_cert \
    t_radmsg \
    t_unhex \
    t_utf8
AM_CFLAGS = -g -Wall -Werror @OPENSSL_INCLUDES@ @TARGET_CFLAGS@
LDADD = $(top_builddir)/librsp.a @OPENSSL_LIBS@
LDFLAGS = @OPENSSL_LDFLAGS@ @TARGET_LDFLAGS@ @LDFLAGS@

TESTS = $(check_PROGRAMS)
