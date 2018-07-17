dnl Copyright (c) 2006-2010, UNINETT AS
dnl Copyright (c) 2010-2013,2016, NORDUnet A/S
dnl See LICENSE for licensing information.

AC_INIT(radsecproxy, 1.7.1, https://radsecproxy.github.io)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_PROG_RANLIB
AC_CHECK_FUNCS([mallopt])

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

AC_CHECK_LIB([nettle], [nettle_sha256_init],,
    [AC_MSG_ERROR([required library nettle not found])])

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

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_SSL
AC_OUTPUT([
	Makefile
	tests/Makefile
])
