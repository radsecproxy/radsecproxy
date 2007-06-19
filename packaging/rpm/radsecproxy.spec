Summary: radsecproxy is a generic RADIUS proxy that provides both RADIUS UDP and TCP/TLS (RadSec) transport.
Name: radsecproxy
Version: 1.0.alpha
Release: 1
Group: Applications/Communications
License: BSD
URL: http://software.uninett.no/radsecproxy
Packager: Arnes <aaa-podpora@arnes.si>
Source: http://software.uninett.no/radsecproxy/radsecproxy-1.0-alpha.tar.gz
Source1: radsecproxy.sysv
Source2: radsecproxy.1
Source3: radsecproxy.conf.5
Requires: openssl >= 0.9.7a

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: openssl-devel >= 0.9.7a

%description
radsecproxy is a generic RADIUS proxy that in addition to to
usual RADIUS UDP transport, also supports TLS (RadSec). The
aim is for the proxy to have sufficient features to be flexible,
while at the same time to be small, efficient and easy to configure.
Currently the executable on Linux is only about 48 Kb, and it uses
about 64 Kb (depending on the number of peers) while running.

The proxy was initially made to be able to deploy RadSec (RADIUS
over TLS) so that all RADIUS communication across network links
could be done using TLS, without modifying existing RADIUS software.
This can be done by running this proxy on the same host as an existing
RADIUS server or client, and configure the existing client/server to
talk to localhost (the proxy) rather than other clients and servers
directly.

There may however be other situations where a RADIUS proxy might be
useful. Some people deploy RADIUS topologies where they want to
route RADIUS messages to the right server. The nodes that do purely
routing could be using a proxy. Some people may also wish to deploy
a proxy on a firewall boundary. Since the proxy supports both IPv4
and IPv6, it could also be used to allow communication in cases
where some RADIUS nodes use only IPv4 and some only IPv6.

%prep
%setup -n %{name}-1.0-alpha

%build
%{__make}

%install
%{__rm} -rf %{buildroot}
%{__install} -D -m0644 radsecproxy.conf-example %{buildroot}%{_docdir}/%{name}-%{version}/radsecproxy.conf-example
%{__install} -D -m0644 AUTHORS                  %{buildroot}%{_docdir}/%{name}-%{version}/AUTHORS
%{__install} -D -m0644 ChangeLog                %{buildroot}%{_docdir}/%{name}-%{version}/ChangeLog
%{__install} -D -m0644 COPYING                  %{buildroot}%{_docdir}/%{name}-%{version}/COPYING
%{__install} -D -m0644 README                   %{buildroot}%{_docdir}/%{name}-%{version}/README
%{__install} -D -m0755 radsecproxy              %{buildroot}%{_sbindir}/radsecproxy
%{__install} -D -m0755 %{SOURCE1}               %{buildroot}%{_initrddir}/radsecproxy
%{__install} -D -m0644 %{SOURCE2}               %{buildroot}%{_mandir}/man1/radsecproxy.1
%{__install} -D -m0644 %{SOURCE3}               %{buildroot}%{_mandir}/man5/radsecproxy.conf.5

%clean
%{__rm} -rf %{buildroot}

%post
/sbin/chkconfig --add radsecproxy

%preun
if [ $1 -eq 0 ]; then
        /sbin/service radsecproxy stop &>/dev/null || :
        /sbin/chkconfig --del radsecproxy
fi

%postun
if [ $1 -ge 1 ]; then
        /sbin/service radsecproxy condrestart &> /dev/null || :
fi

%files
%defattr(-, root, root, 0755)
%config %{_initrddir}/radsecproxy
%{_sbindir}/radsecproxy
%doc %{_docdir}/%{name}-%{version}/AUTHORS
%doc %{_docdir}/%{name}-%{version}/ChangeLog
%doc %{_docdir}/%{name}-%{version}/COPYING
%doc %{_docdir}/%{name}-%{version}/README
%doc %{_docdir}/%{name}-%{version}/radsecproxy.conf-example
%doc %{_mandir}/man1/radsecproxy.1.gz
%doc %{_mandir}/man5/radsecproxy.conf.5.gz

%changelog
* Thu Jun 07 2007 Rok Papez <aaa-podpora@arnes.si> - 1.0-alpha.1
- Initial packaging of the 1.0-alpha.1 release 
- Added SysV/RedHat init script
- Added radsecproxy manages
