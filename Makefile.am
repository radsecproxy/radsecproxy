sbin_PROGRAMS        = radsecproxy

radsecproxy_SOURCES = radsecproxy.c \
                      gconfig.c \
                      util.c \
                      debug.c \
                      list.c \
                      hash.c \
		      tlv11.c \
		      radmsg.c \
		      udp.c \
		      tcp.c \
		      tls.c \
		      dtls.c \
                      radsecproxy.h \
                      gconfig.h \
                      debug.h \
                      util.h \
                      list.h \
                      hash.h \
		      tlv11.h \
		      radmsg.h \
		      udp.h \
		      tcp.h \
		      tls.h \
		      dtls.h

radsecproxy_CFLAGS  = -g -Wall -pedantic -pthread -DRADPROT_UDP -DRADPROT_TCP -DRADPROT_TLS -DRADPROT_DTLS @SSL_CFLAGS@ @TARGET_CFLAGS@
radsecproxy_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
radsecproxy_LDADD   = @SSL_LIBS@

dist_sysconf_DATA   = $(srcdir)/radsecproxy.conf-example
dist_man_MANS       = radsecproxy.1 radsecproxy.conf.5
