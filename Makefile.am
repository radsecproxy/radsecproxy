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

radsecproxy_CFLAGS  = -g -Wall @SSL_CFLAGS@ @TARGET_CFLAGS@
radsecproxy_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
radsecproxy_LDADD   = @SSL_LIBS@

catgconf_CFLAGS     = -g -Wall @TARGET_CFLAGS@
catgconf_LDFLAGS    = @TARGET_LDFLAGS@

EXTRA_DIST = radsecproxy.conf-example \
		radsecproxy.1 \
		radsecproxy.conf.5.xml

man: $(srcdir)/radsecproxy.conf.5.xml
	docbook2x-man $<

clean-local:
	-rm radsecproxy.conf.5
