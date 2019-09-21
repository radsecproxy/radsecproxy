#!/bin/sh
set -ex
yum install rpmdevtools gcc make nettle-devel openssl-devel
rpmdev-setuptree
spectool -g -R radsecproxy.spec
cp patch-* *.service ~/rpmbuild/SOURCES/
rpmbuild -bb radsecproxy.spec
