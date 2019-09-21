# CentOS/Fedora package for radsecproxy

  * Project page: https://radsecproxy.github.io/
  * Package page: https://copr.fedorainfracloud.org/coprs/jornane/radsecproxy/


# Install

## CentOS / Red Hat

	yum install yum-plugin-copr
	yum copr enable jornane/radsecproxy
	yum install radsecproxy


## Fedora

	dnf install dnf-plugins-core
	dnf copr enable jornane/radsecproxy
	dnf install radsecproxy


# Build locally

	sh build.sh

If everything goes well, the resulting RPM file will be in `~/rpmbuild/RPMS`
