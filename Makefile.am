AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = radsecproxy
bin_PROGRAMS  = catgconf

radsecproxy_SOURCES = radsecproxy.c \
                      tlscommon.c \
                      gconfig.c \
                      util.c \
                      debug.c \
                      list.c \
                      hash.c \
                      tlv11.c \
                      hostport.c \
                      radmsg.c \
                      udp.c \
                      tcp.c \
                      tls.c \
                      dtls.c \
                      radsecproxy.h \
                      tlscommon.h \
                      gconfig.h \
                      debug.h \
                      util.h \
                      list.h \
                      hash.h \
                      tlv11.h \
                      hostport.h \
                      radmsg.h \
                      udp.h \
                      tcp.h \
                      tls.h \
                      dtls.h

catgconf_SOURCES    = debug.c \
                      util.c \
                      gconfig.c \
                      catgconf.c

radsecproxy_CFLAGS  = -g @SSL_CFLAGS@ @TARGET_CFLAGS@
radsecproxy_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
radsecproxy_LDADD   = @SSL_LIBS@

catgconf_CFLAGS     = -g @TARGET_CFLAGS@
catgconf_LDFLAGS    = @TARGET_LDFLAGS@

dist_sysconf_DATA   = $(srcdir)/radsecproxy.conf-example
dist_man_MANS       = radsecproxy.1 radsecproxy.conf.5
