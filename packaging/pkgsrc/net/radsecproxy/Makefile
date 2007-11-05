# $NetBSD: Makefile,v 1.0 2007/11/02 11:00:00 kolla Exp $

DISTNAME=	radsecproxy-1.0p1
CATEGORIES=	net
MASTER_SITES=	http://software.uninett.no/radsecproxy/

MAINTAINER=	netbsd@kolla.no
HOMEPAGE=	http://software.uninett.no/radsecproxy/
COMMENT=	RADIUS proxy that also supports RadSec

# WRKSRC=		${WRKDIR}/radsecproxy-1.0p1

EGDIR=		${PREFIX}/share/examples/radsecproxy
CONF_FILES=     ${EGDIR}/radsecproxy.conf ${PKG_SYSCONFDIR}/radsecproxy.conf

RCD_SCRIPTS=	radsecproxy

.include "../../mk/bsd.prefs.mk"

INSTALLATION_DIRS=	sbin ${PKGMANDIR}/man1 ${PKGMANDIR}/man5 ${EGDIR}

do-install:
	${INSTALL_MAN} ${WRKSRC}/radsecproxy.1 ${PREFIX}/${PKGMANDIR}/man1
	${INSTALL_MAN} ${WRKSRC}/radsecproxy.conf.5 ${PREFIX}/${PKGMANDIR}/man5
	${INSTALL_PROGRAM} ${WRKSRC}/radsecproxy ${PREFIX}/sbin
	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/README ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/AUTHORS ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/COPYING ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/INSTALL ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/ChangeLog ${PREFIX}/share/doc/radsecproxy
	${INSTALL_DATA} ${WRKSRC}/radsecproxy.conf-example ${EGDIR}/radsecproxy.conf

.include "../../mk/bsd.pkg.mk"
