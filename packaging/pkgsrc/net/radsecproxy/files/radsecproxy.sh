#!/bin/sh
#
# PROVIDE: radsecproxy
# REQUIRE: network
#

if [ -f /etc/rc.subr ]
then
	. /etc/rc.subr
fi

name="radsecproxy"
rcvar=${name}
command="/usr/pkg/sbin/${name}"
command_args="-c /usr/pkg/etc/${name}.conf"

if [ -f /etc/rc.subr ]
then
	load_rc_config $name
	run_rc_command "$1"
else
	echo -n ' ${name}'
	exec ${command} ${command_args}
fi
