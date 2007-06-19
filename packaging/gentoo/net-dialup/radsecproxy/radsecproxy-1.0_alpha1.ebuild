# Copyright 1999-2007 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: radsecproxy-1.0_alpha1.ebuild 12 2007-06-14 19:53:35Z kolla $

inherit eutils

MY_P=${P%_alpha1}-alpha-p1
S=${S%_alpha1}-alpha-p1

DESCRIPTION="RADIUS/RADSEC Proxy"
HOMEPAGE="http://software.uninett.no/radsecproxy"
SRC_URI="http://software.uninett.no/${PN}/${MY_P}.tar.gz"

LICENSE=""
SLOT="0"
KEYWORDS="x86 ~alpha ~amd64 ~arm ~ia64 ~m68k ~mips ~ppc ~ppc64 ~s390"

IUSE=""

DEPEND="dev-libs/openssl"
RDEPEND="dev-libs/openssl"

src_unpack() {
	unpack ${A}
	# Use sbin instead of bin
	sed 's:^bin_PROGRAMS:sbin_PROGRAMS:' -i "${S}"/Makefile.am
}

src_install() {
	einstall || die
	dodoc AUTHORS COPYING ChangeLog INSTALL NEWS README
	newinitd "${FILESDIR}/${PN}.initd" ${PN}
	newconfd "${FILESDIR}/${PN}.confd" ${PN}
}

pkg_postinst () {
	echo
	elog "Example config exists as /etc/radsecproxy.conf-example"
	elog "Copy this to /etc/radsecproxy.conf and edit to suit your needs"
	echo
}
