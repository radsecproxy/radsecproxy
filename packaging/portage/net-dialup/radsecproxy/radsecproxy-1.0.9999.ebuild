# Copyright 1999-2007 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

inherit eutils subversion

DESCRIPTION="Radius/RadSec Proxy Server - 1.0 release tree from SVN"
HOMEPAGE="http://software.uninett.no/radsecproxy"
ESVN_REPO_URI="https://svn.testnett.uninett.no/${PN}/branches/release-1.0"
SRC_URI=""

LICENSE="public-domain"
SLOT="0"
KEYWORDS=""
IUSE=""

DEPEND="dev-libs/openssl"
RDEPEND="dev-libs/openssl"

S=${WORKDIR}/release-1.0

src_unpack() {
	subversion_src_unpack
	touch AUTHORS COPYING ChangeLog INSTALL NEWS README
	autoreconf --force --install
	mkdir -pv "${S}"/init.d "${S}"/conf.d
	cat >"${S}"/init.d/"${PN}" << EOF
#! /sbin/runscript

depend() {
	use logger dns
	need net
}

CMD="/usr/sbin/radsecproxy"

start() {
	ebegin "Starting radsecproxy"
	if test -n "\${OPTS}" ; then
		start-stop-daemon --chuid \${CMDUSER:-nobody} --start --exec \${CMD} -- \${OPTS}
	else
		start-stop-daemon --chuid \${CMDUSER:-nobody} --start --exec \${CMD}
	fi
	eend \${?}
}

stop() {
	ebegin "Stopping radsecproxy"
	start-stop-daemon --stop --exec \${CMD}
	eend \${?}
}
EOF
	cat >"${S}"/conf.d/"${PN}" << EOF
# Options for radsecproxy
#
# -d specifies the debug level.
# 
# It must be set to 1, 2, 3 or  4, where  1 logs
# only  serious errors, and 4 logs everything.
#
# The default is 3 which logs errors, warnings and
# some informational messages.

# OPTS="-d 4"'
# CMDUSER="nobody"
EOF
}

src_install() {
	einstall || die
	doinitd "${S}"/init.d/"${PN}"
	doconfd "${S}"/conf.d/"${PN}"
	dodoc AUTHORS COPYING ChangeLog INSTALL NEWS README
}

pkg_postinst () {
	einfo
	elog "Example config exists as /etc/radsecproxy.conf-example"
	elog "Copy this to /etc/radsecproxy.conf and edit to suit your needs"
	einfo
}
