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
                      fticks.c \
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
                      dtls.h \
		      fticks.h

catgconf_SOURCES    = debug.c \
                      util.c \
                      gconfig.c \
                      catgconf.c

radsecproxy_CFLAGS  = -g -Wall -fno-strict-aliasing @SSL_CFLAGS@ @TARGET_CFLAGS@
radsecproxy_LDFLAGS = @SSL_LDFLAGS@ @TARGET_LDFLAGS@
radsecproxy_LDADD   = @SSL_LIBS@

catgconf_CFLAGS     = -g -Wall -fno-strict-aliasing @TARGET_CFLAGS@
catgconf_LDFLAGS    = @TARGET_LDFLAGS@

dist_man_MANS = radsecproxy.1 $(GENMANPAGES)
EXTRA_DIST = LICENSE THANKS radsecproxy.conf-example radsecproxy.conf.5.xml \
	tools/naptr-eduroam.sh tools/radsec-dynsrv.sh tools/README

if HAVE_DOCBOOK2X_MAN
GENMANPAGES = radsecproxy.conf.5
endif

radsecproxy.conf.5: $(srcdir)/radsecproxy.conf.5.xml
	docbook2x-man $<

# Build HTML version of radsecproxy.conf.5.  NOTE: Only tested with
# 'openjade' package installed on Ubuntu 9.10.
html: $(srcdir)/radsecproxy.conf.5.xml
	-openjade -E2000 -t sgml-raw -d /usr/share/sgml/docbook/stylesheet/dsssl/modular/html/docbook.dsl -o radsecproxy.conf.html $<

clean-local:
	-rm radsecproxy.conf.5
