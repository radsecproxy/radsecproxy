Name:			radsecproxy
Version:		1.8.0
Release:		4%{?dist}
Summary:		A generic RADIUS proxy

License:		BSD
URL:			https://radsecproxy.github.io/
Source0:		https://github.com/radsecproxy/%{name}/releases/download/%{version}/%{name}-%{version}.tar.gz
Source1:		radsecproxy.service
Patch0:			patch-radsecproxy.conf-example
BuildRequires:		gcc
BuildRequires:		make
BuildRequires:		nettle-devel
BuildRequires:		openssl-devel
%if 0%{?fedora} >= 30
BuildRequires:		systemd-rpm-macros
%else
BuildRequires:		systemd
%endif
Requires(pre):		shadow-utils
Requires(preun):	systemd-units
Requires(postun):	systemd-units

%description
radsecproxy is a generic RADIUS proxy that in addition to usual RADIUS UDP
transport, also supports TLS (RadSec), as well as RADIUS over TCP and DTLS.
The aim is for the proxy to have sufficient features to be flexible, while
at the same time to be small, efficient and easy to configure.

%pre
/usr/bin/getent group  radsecproxy >/dev/null || /usr/sbin/groupadd -r radsecproxy
/usr/bin/getent passwd radsecproxy >/dev/null || \
	/usr/sbin/useradd -r -g radsecproxy -d /var/empty -s /sbin/nologin -c "radsecproxy user" radsecproxy
exit 0

%preun
%systemd_preun radsecproxy.service

%postun
%systemd_postun_with_restart radsecproxy.service
if [ $1 -eq 0 ]; then # uninstall
	/usr/bin/getent passwd radsecproxy >/dev/null && /usr/sbin/userdel  radiusd >/dev/null 2>&1
	/usr/bin/getent group  radsecproxy >/dev/null && /usr/sbin/groupdel radiusd >/dev/null 2>&1
fi
exit 0

%prep
%autosetup

%build
%configure
%make_build

%install
%make_install
mkdir -p %{buildroot}%{_sysconfdir} %{buildroot}%{_unitdir}
cp radsecproxy.conf-example %{buildroot}%{_sysconfdir}/radsecproxy.conf
cp %{SOURCE1} %{buildroot}%{_unitdir}/radsecproxy.service

%files
%{_bindir}/radsecproxy-conf
%{_bindir}/radsecproxy-hash
%{_sbindir}/radsecproxy
%{_mandir}/man1/radsecproxy-hash.1.gz
%{_mandir}/man1/radsecproxy.1.gz
%{_mandir}/man5/radsecproxy.conf.5.gz
%{_unitdir}/radsecproxy.service
%attr(0640,root,radsecproxy) %config(noreplace) %{_sysconfdir}/radsecproxy.conf

%license LICENSE
%doc ChangeLog AUTHORS NEWS README THANKS

%changelog
* Tue Sep 17 2019 Jørn Åne de Jong <jorn.dejong@uninett.no>
- Initial build.
