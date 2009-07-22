# $NetBSD: Makefile,v 1.2 2009/04/01 15:20:00 kolla Exp $

DISTNAME=	radsecproxy-1.3.1
CATEGORIES=	net
MASTER_SITES=	http://software.uninett.no/radsecproxy/

MAINTAINER=	netbsd@kolla.no
HOMEPAGE=	http://software.uninett.no/radsecproxy/
COMMENT=	RADIUS proxy that supports RadSec

EGDIR=		${PREFIX}/share/examples/radsecproxy
CONF_FILES=     ${EGDIR}/radsecproxy.conf ${PKG_SYSCONFDIR}/radsecproxy.conf

BUILDLINK_API_DEPENDS.openssl+= openssl>=0.9.7

RCD_SCRIPTS=	radsecproxy

.include "../../mk/bsd.prefs.mk"

INSTALLATION_DIRS=	sbin ${PKGMANDIR}/man1 ${PKGMANDIR}/man5 ${EGDIR}

CONFIGURE_ARGS+= --sysconfdir=${PKG_SYSCONFDIR}
CONFIGURE_ARGS+= --enable-udp
CONFIGURE_ARGS+= --enable-tls
CONFIGURE_ARGS+= --disable-dtls # DTLS is not supported in OpenSSL on *BSD yet!
CONFIGURE_ARGS+= --disable-tcp  # Enable only if you _really_ need it

do-patch:
	for f in ${WRKSRC}/* ; do \
		${SED} 's%\(/etc/radsecproxy.conf\)%/usr/pkg&%g' < $${f} > $${f}.tmp ; mv $${f}.tmp $${f} ; \
	done

do-configure:
	cd ${WRKSRC} && sh ./configure ${CONFIGURE_ARGS}

# do-build:
# 	cd ${WRKSRC} && make && make catgconf

do-install:
	${INSTALL_MAN} ${WRKSRC}/radsecproxy.1 ${PREFIX}/${PKGMANDIR}/man1
	${INSTALL_MAN} ${WRKSRC}/radsecproxy.conf.5 ${PREFIX}/${PKGMANDIR}/man5
	${INSTALL_PROGRAM} ${WRKSRC}/radsecproxy ${PREFIX}/sbin
	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/README ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/AUTHORS ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/COPYING ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/LICENSE ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/INSTALL ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/ChangeLog ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/radsecproxy.conf-example ${EGDIR}/radsecproxy.conf
	${INSTALL_DATA} ${WRKSRC}/radsec-dynsrv.sh ${EGDIR}/radsec-dynsrv.sh
#	${INSTALL_PROGRAM} ${WRKSRC}/catgconf ${PREFIX}/sbin/radsecproxy-catgconf

.include "../../mk/bsd.pkg.mk"
