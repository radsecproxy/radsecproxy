# -*- Autoconf -*- script for libradsec.

AC_PREREQ([2.65])
AC_INIT([libradsec], [0.0.1-dev], [linus+libradsec@nordu.net])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([radsec.c])
AC_CONFIG_HEADERS([config.h])
AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CC

# Enable-knobs.
AH_TEMPLATE([RS_ENABLE_TLS], [TLS (RadSec) enabled])
AH_TEMPLATE([RADPROT_TLS], [])
AC_ARG_ENABLE([tls], AS_HELP_STRING([--enable-tls], [enable TLS (RadSec)]),
    [AC_DEFINE([RS_ENABLE_TLS])
     AC_DEFINE([RADPROT_TLS])])

# Checks for libraries.
AC_CHECK_LIB([confuse], [cfg_init],,
    AC_MSG_ERROR([required library libconfuse not found]))
AC_CHECK_LIB([event_core], [event_get_version],,
    AC_MSG_ERROR([required library libevent_core not found]))
AC_CHECK_LIB([freeradius-radius], [rad_alloc],,
    AC_MSG_ERROR([required library libfreeradius-radius not found]))
dnl TODO: Only do this if --enable-tls or --enable-dtls.
#AC_CHECK_LIB([ssl], [SSL_new],,
#    AC_MSG_ERROR([required library libssl not found]))
AC_CHECK_LIB([event_openssl], [bufferevent_openssl_socket_new],,
    AC_MSG_ERROR([required library event_openssl not found]))

# Checks for header files.
AC_CHECK_HEADERS(
    [netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset socket strdup strerror strrchr])

AC_CONFIG_FILES([Makefile
		 include/Makefile
                 examples/Makefile])
AC_OUTPUT
