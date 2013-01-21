#! /bin/sh

[ -d m4 ] || mkdir m4
[ -d build-aux ] || mkdir build-aux

if [ -x "`which autoreconf 2>/dev/null`" ] ; then
   exec autoreconf -ivf
fi

aclocal -I m4 && \
    autoheader && \
    libtoolize --automake -c && \
    autoconf && \
    automake --add-missing --copy
