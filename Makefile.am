bin_PROGRAMS        = radsecproxy

radsecproxy_SOURCES = radsecproxy.c \
                      util.c \
                      debug.c \
                      radsecproxy.h \
                      debug.h

radsecproxy_CFLAGS  = -g -Wall -pedantic -pthread @SSL_CFLAGS@
radsecproxy_LDFLAGS = @SSL_LDFLAGS@
radsecproxy_LDADD   = @SSL_LIBS@

sysconfdir          = ${prefix}/etc/radsecproxy
dist_sysconf_DATA   = $(srcdir)/radsecproxy.conf-example
