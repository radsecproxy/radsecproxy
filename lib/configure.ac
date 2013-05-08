# -*- Autoconf -*- script for libradsec.

AC_PREREQ([2.63])
AC_INIT([libradsec], [0.0.4.dev], [linus+libradsec@nordu.net])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([radsec.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE
LT_INIT

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([confuse], [cfg_init],,
    AC_MSG_ERROR([required library libconfuse not found]))
AC_CHECK_LIB([event_core], [event_get_version],,
    AC_MSG_ERROR([required library libevent_core not found]))

# Enable-knobs.
## Enable TLS (RadSec).
AH_TEMPLATE([RS_ENABLE_TLS], [TLS (RadSec) enabled])
AH_TEMPLATE([RADPROT_TLS], [])  dnl Legacy.
AC_ARG_ENABLE([tls], AS_HELP_STRING([--enable-tls], [enable TLS (RadSec)]),
    [AC_CHECK_LIB([event_openssl], [bufferevent_openssl_socket_new],,
         AC_MSG_ERROR([required library event_openssl not found]))
     AC_DEFINE([RS_ENABLE_TLS])
     AC_DEFINE([RADPROT_TLS])]) dnl Legacy.
AM_CONDITIONAL([RS_ENABLE_TLS], [test "${enable_tls+set}" = set])
### Define WITHOUT_OPENSSL for radius/client.h.
if test -z "$enable_tls"; then
    CPPFLAGS="$CPPFLAGS -DWITHOUT_OPENSSL"
fi
## Enable TLS-PSK (preshared keys).
AH_TEMPLATE([RS_ENABLE_TLS_PSK], [TLS-PSK (TLS preshared keys) enabled])
AC_ARG_ENABLE([tls-psk], AS_HELP_STRING([--enable-tls-psk], [enable TLS-PSK (TLS preshared keys)]),
    [AC_CHECK_LIB([ssl], [SSL_set_psk_client_callback],,
         AC_MSG_ERROR([required library openssl with SSL_set_psk_client_callback() not found]))
     AC_DEFINE([RS_ENABLE_TLS_PSK])])
AM_CONDITIONAL([RS_ENABLE_TLS_PSK], [test "${enable_tls_psk+set}" = set])

# Checks for header files.
AC_CHECK_HEADERS(
    [sys/time.h time.h netdb.h netinet/in.h stdint.h stdlib.h strings.h string.h \
     sys/socket.h unistd.h syslog.h sys/select.h fcntl.h arpa/inet.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset socket strdup strerror strrchr])

AC_CONFIG_FILES([Makefile libradsec.spec
                 radsecproxy/Makefile
                 radius/Makefile
                 include/Makefile
                 examples/Makefile
                 tests/Makefile])
AC_OUTPUT
