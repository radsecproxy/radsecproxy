#! /bin/sh
if [ -x "`which autoreconf 2>/dev/null`" ] ; then
   exec autoreconf -ivf
fi

aclocal -I m4 && \
    autoheader && \
    libtoolize --automake -c && \
    autoconf && \
    automake --add-missing --copy
