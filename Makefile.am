sbin_PROGRAMS        = radsecproxy

radsecproxy_SOURCES = radsecproxy.c \
                      gconfig.c \
                      util.c \
                      debug.c \
                      list.c \
                      radsecproxy.h \
                      gconfig.h \
                      debug.h \
                      util.h \
                      list.h

radsecproxy_CFLAGS  = -g -Wall -pedantic -pthread @SSL_CFLAGS@
radsecproxy_LDFLAGS = @SSL_LDFLAGS@
radsecproxy_LDADD   = @SSL_LIBS@

dist_sysconf_DATA   = $(srcdir)/radsecproxy.conf-example
dist_man_MANS       = radsecproxy.1 radsecproxy.conf.5
