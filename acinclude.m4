dnl Based on the one from the Boinc project by Reinhard

AC_DEFUN([AX_CHECK_SSL],
[AC_MSG_CHECKING(for OpenSSL)
SSL_DIR=
found_ssl="no"
AC_ARG_WITH(ssl,
    AS_HELP_STRING([--with-ssl],
       [Use SSL (in specified installation directory)]),
    [check_ssl_dir="$withval"],
    [check_ssl_dir=])
for dir in $check_ssl_dir /usr /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local ; do
   ssldir="$dir"
   if test -f "$dir/include/openssl/ssl.h"; then
     found_ssl="yes";
     SSL_DIR="${ssldir}"
     SSL_CFLAGS="-I$ssldir/include -I$ssldir/include/openssl";
     break;
   fi
   if test -f "$dir/include/ssl.h"; then
     found_ssl="yes";
     SSL_DIR="${ssldir}"
     SSL_CFLAGS="-I$ssldir/include/";
     break
   fi
done
AC_MSG_RESULT($found_ssl)
if test x_$found_ssl != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find SSL libraries.

  Please install OpenSSL or specify installation directory with
  --with-ssl=(dir).
----------------------------------------------------------------------
])
else
        printf "OpenSSL found in $ssldir\n";
	SSL_LIBS="-lssl -lcrypto";
        SSL_LDFLAGS="-L$ssldir/lib";
	AC_DEFINE_UNQUOTED([USE_OPENSSL],[1],
	  ["Define to 1 if you want to use the OpenSSL crypto library"])
	AC_SUBST(SSL_CFLAGS)
	AC_SUBST(SSL_LDFLAGS)
	AC_SUBST(SSL_LIBS)
fi
])dnl
