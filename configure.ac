dnl Copyright (c) 2006-2010, UNINETT AS
dnl Copyright (c) 2010-2012, NORDUnet A/S
dnl See LICENSE for licensing information.

AC_INIT(radsecproxy, 1.6.1-dev, radsecproxy@uninett.no)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_PROG_RANLIB
udp=yes
AC_ARG_ENABLE(udp,
  [  --enable-udp whether to enable UDP transport: yes/no; default yes ],
  [ if test "x$enableval" = "xyes" -o "x$enableval" = "xno" ; then
      udp=$enableval
    else
      echo "--enable-udp argument must be yes or no"
      exit -1
    fi
  ])
 
tcp=yes
AC_ARG_ENABLE(tcp,
  [  --enable-tcp whether to enable TCP transport: yes/no; default yes ],
  [ if test "x$enableval" = "xyes" -o "x$enableval" = "xno" ; then
      tcp=$enableval
    else
      echo "--enable-tcp argument must be yes or no"
      exit -1
    fi
  ])
 
tls=yes
AC_ARG_ENABLE(tls,
  [  --enable-tls whether to enable TLS (RadSec) transport: yes/no; default yes ],
  [ if test "x$enableval" = "xyes" -o "x$enableval" = "xno" ; then
      tls=$enableval
    else
      echo "--enable-tls argument must be yes or no"
      exit -1
    fi
  ])
 
dtls=yes
AC_ARG_ENABLE(dtls,
  [  --enable-dtls whether to enable DTLS transport: yes/no; default yes ],
  [ if test "x$enableval" = "xyes" -o "x$enableval" = "xno" ; then
      dtls=$enableval
    else
      echo "--enable-dtls argument must be yes or no"
      exit -1
    fi
  ])

AC_ARG_ENABLE(fticks,
AC_HELP_STRING([--enable-fticks],[build with F-Ticks support [default=no]]),
[case $enableval in
yes|no) ;;
*) AC_MSG_ERROR([bad value $enableval for --enable-fticks, need yes or no]) ;;
esac],
[enable_fticks=no])

if test "$enable_fticks" = "yes"; then
AC_CHECK_LIB([nettle], [nettle_sha256_init],,
    [AC_MSG_WARN([required library nettle not found, fticks support disabled])
     enable_fticks=no])
fi

if test "$enable_fticks" = "yes"; then
AC_DEFINE([WANT_FTICKS], [1])
fi
AM_CONDITIONAL(WANT_FTICKS, test "$enable_fticks" = "yes")

dnl Check if we're on Solaris and set CFLAGS accordingly
AC_CANONICAL_SYSTEM
case "${target_os}" in
  solaris*)
    TARGET_CFLAGS="-DSYS_SOLARIS9 -D_POSIX_PTHREAD_SEMANTICS"
    if test "$GCC" != yes ; then
      TARGET_CFLAGS="$TARGET_CFLAGS -mt"
    else
      TARGET_CFLAGS="$TARGET_CFLAGS -pthreads"
    fi
    TARGET_LDFLAGS="-lpthread -lsocket -lnsl"
    ;;
  *)
    TARGET_CFLAGS="-Wall -pedantic -Wno-long-long -pthread"
    TARGET_LDFLAGS=""
  esac
dnl Adding enabled options
if test "x$udp" = "xyes" ; then
  echo "UDP transport enabled"
  TARGET_CFLAGS="$TARGET_CFLAGS -DRADPROT_UDP"
fi
if test "x$tcp" = "xyes" ; then
  echo "TCP transport enabled"
  TARGET_CFLAGS="$TARGET_CFLAGS -DRADPROT_TCP"
fi
if test "x$tls" = "xyes" ; then
  echo "TLS (RadSec) transport enabled"
  TARGET_CFLAGS="$TARGET_CFLAGS -DRADPROT_TLS"
fi
if test "x$dtls" = "xyes" ; then
  echo "DTLS transport enabled"
  TARGET_CFLAGS="$TARGET_CFLAGS -DRADPROT_DTLS"
fi
 
AC_ARG_ENABLE(
  experimental_dyndisc,
  AC_HELP_STRING([--enable-experimental-dyndisc],
                 [enable experimental code for dynamic discovery [default=no]]),
  [case $enableval in
     yes|no) ;;
     *) AC_MSG_ERROR([bad value $enableval for --enable-experimental-dyndisc, need yes or no]) ;;
     esac],
  [enable_experimental_dyndisc=no])
if test "$enable_experimental_dyndisc" = "yes"; then
  AC_DEFINE([ENABLE_EXPERIMENTAL_DYNDISC], [1])
fi
AM_CONDITIONAL(ENABLE_EXPERIMENTAL_DYNDISC,
               test "$enable_experimental_dyndisc" = "yes")


AC_ARG_VAR([DOCBOOK2X_MAN], [docbook2x-man])
AC_CHECK_PROG([DOCBOOK2X_MAN], [docbook2x-man], [yes])
AM_CONDITIONAL(HAVE_DOCBOOK2X_MAN, test "$DOCBOOK2X_MAN" = "yes")

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_SSL
AC_OUTPUT([
	Makefile
	tests/Makefile
])
