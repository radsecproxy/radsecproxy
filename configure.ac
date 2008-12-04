AC_INIT(radsecproxy, 1.3-alpha, venaas@uninett.no)
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
dnl Check if we're on Solaris and set CFLAGS accordingly
AC_CANONICAL_SYSTEM
case "${target_os}" in
  solaris*)
    TARGET_CFLAGS="-DSYS_SOLARIS9 -D_POSIX_PTHREAD_SEMANTICS"
    TARGET_LDFLAGS="-lsocket"
    ;;
  *)
    TARGET_CFLAGS=""
    TARGET_LDFLAGS=""
  esac
AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_SSL
AC_OUTPUT(Makefile)
