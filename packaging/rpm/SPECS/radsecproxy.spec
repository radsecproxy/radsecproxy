Name:           radsecproxy
Version:        1.8.0
Release:        1%{?dist}
Summary:        a generic RADIUS proxy

License:        NORDUnet
URL:            https://radsecproxy.github.io/
Source0:        https://github.com/%{name}/%{name}/releases/download/%{version}/%{name}-%{version}.tar.gz
Source1:	radsecproxy.service
Source2:	radsecproxy.logrotate
Source3:	radsecproxy.rsyslog
Source4:	radsecproxy.tmpfiles
BuildRequires: gcc
BuildRequires: openssl-devel
Requires(post): policycoreutils-python
Requires(postun): policycoreutils-python
#Requires:       

%description
radsecproxy is a generic RADIUS proxy that in addition to to usual RADIUS UDP transport, also supports TLS (RadSec), as well as RADIUS over TCP and DTLS. The aim is for the proxy to have sufficient features to be flexible, while at the same time to be small, efficient and easy to configure.

The proxy was initially made to be able to deploy RadSec (RADIUS over TLS) so that all RADIUS communication across network links could be done using TLS, without modifying existing RADIUS software. This can be done by running this proxy on the same host as an existing RADIUS server or client, and configure the existing client/server to talk to localhost (the proxy) rather than other clients and servers directly.

There are however other situations where a RADIUS proxy might be useful. Some people deploy RADIUS topologies where they want to route RADIUS messages to the right server. The nodes that do purely routing could be using a proxy. Some people may also wish to deploy a proxy on a site boundary. Since the proxy supports both IPv4 and IPv6, it could also be used to allow communication in cases where some RADIUS nodes use only IPv4 and some only IPv6.

%prep
%autosetup
cp -p %SOURCE1 %SOURCE2 %SOURCE3 %SOURCE4 .

%build
%configure
make %{?_smp_mflags}

%pre
getent group radsecproxy >/dev/null || groupadd -r radsecproxy
getent passwd radsecproxy >/dev/null || useradd -r -g radsecproxy radsecproxy
exit 0

%install
rm -rf $RPM_BUILD_ROOT
%make_install
mkdir -p %{buildroot}%{_sysconfdir}
cp radsecproxy.conf-example %{buildroot}%{_sysconfdir}/radsecproxy.conf
mkdir -p %{buildroot}%{_unitdir}
cp radsecproxy.service %{buildroot}%{_unitdir}/%{name}.service
mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
cp radsecproxy.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
mkdir -p %{buildroot}%{_sysconfdir}/rsyslog.d
cp radsecproxy.rsyslog %{buildroot}%{_sysconfdir}/rsyslog.d/%{name}.conf
mkdir -p %{buildroot}%{_prefix}/lib/tmpfiles.d
cp radsecproxy.tmpfiles %{buildroot}%{_prefix}/lib/tmpfiles.d/%{name}.conf
#mkdir -p %{buildroot}%{_localstatedir}/log/%{name}
mkdir -p %{buildroot}%{_localstatedir}/log
touch %{buildroot}%{_localstatedir}/log/%{name}.log
mkdir -p %{buildroot}%{_localstatedir}/run/%{name}

%post
semanage fcontext -a -t radiusd_exec_t '%{_sbindir}/radsecproxy' 2>/dev/null || :
restorecon %{_sbindir}/radsecproxy || :
#semanage fcontext -a -t radiusd_log_t '%{_localstatedir}/log/%{name}(/[^/]*)?' 2>/dev/null || :
#test -d %{_localstatedir}/log/%{name} && restorecon -R %{_localstatedir}/log/%{name} || :
semanage fcontext -a -t radiusd_unit_file_t '%{_unitdir}/%{name}.service' 2>/dev/null || :
restorecon %{_unitdir}/%{name}.service || :
systemctl daemon-reload
systemctl try-restart %{name}.service
systemctl try-restart rsyslog.service

%postun
semanage fcontext -d -t radiusd_exec_t '%{_sbindir}/radsecproxy' 2>/dev/null || :
#semanage fcontext -d -t radiusd_log_t '%{_localstatedir}/log/%{name}(/[^/]*)?' 2>/dev/null || :
semanage fcontext -d -t radiusd_unit_file_t '%{_unitdir}/%{name}.service' 2>/dev/null || :

%files
%doc
%{_bindir}/radsecproxy-hash
%{_bindir}/radsecproxy-conf
%{_sbindir}/radsecproxy
%{_mandir}/man1/radsecproxy-hash.1.gz
%{_mandir}/man1/radsecproxy.1.gz
%{_mandir}/man5/radsecproxy.conf.5.gz
%{_unitdir}/%{name}.service
%{_prefix}/lib/tmpfiles.d/%{name}.conf
%attr(0640,root,radsecproxy) %config(noreplace) %{_sysconfdir}/radsecproxy.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%config(noreplace) %{_sysconfdir}/rsyslog.d/%{name}.conf
# %%attr(0750,radsecproxy,radsecproxy) %dir %{_localstatedir}/log/%{name}
%ghost %attr(0644,root,root) %{_localstatedir}/log/%{name}.log
%attr(0750,radsecproxy,radsecproxy) %dir %{_localstatedir}/run/%{name}

%changelog
