#! /bin/sh

# Example script!
# This script looks up radsec srv records in DNS for the one
# realm given as argument, and creates a server template based
# on that. It currently ignores weight markers, but does sort
# servers on priority marker, lowest number first.
# For host command this is coloumn 5, for dig it is coloumn 1.

usage() {
    /bin/echo "Usage: ${0} <realm>"
    exit 1
}

test -n "${1}" || usage

REALM="${1}"
DIGCMD=$(command -v dig)
HOSTCMD=$(command -v host)

dig_it_srv() {
    ${DIGCMD} +short srv $SRV_HOST | sort -k1 |
    while read line ; do
	set $line ; PORT=$3 ; HOST=$4
	/bin/echo -e "\thost ${HOST%.}:${PORT}"
    done
}

dig_it_naptr() {
    ${DIGCMD} +short naptr ${REALM} | grep x-eduroam:radius.tls | sort -k1 |
    while read line ; do
	set $line ; TYPE=$3 ; HOST=$6
	if [ "$TYPE" = "\"s\"" ]; then { 
		SRV_HOST=${HOST%.}
		dig_it_srv; };
	fi
    done
}

host_it_srv() {
    ${HOSTCMD} -t srv $SRV_HOST | sort -k5 | 
    while read line ; do
	set $line ; PORT=$7 ; HOST=$8 
	/bin/echo -e "\thost ${HOST%.}:${PORT}"
    done
}

host_it_naptr() {
    ${HOSTCMD} -t naptr ${REALM} | grep x-eduroam:radius.tls | sort -k5 | 
    while read line ; do
	set $line ; TYPE=$7 ; HOST=${10}
	if [ "$TYPE" = "\"s\"" ]; then {
		SRV_HOST=${HOST%.}
		host_it_srv; }; fi
	
    done
}

if test -x "${DIGCMD}" ; then
    SERVERS=$(dig_it_naptr)
elif test -x "${HOSTCMD}" ; then
    SERVERS=$(host_it_naptr)
else
    /bin/echo "${0} requires either \"dig\" or \"host\" command."
    exit 1
fi

if test -n "${SERVERS}" ; then
    /bin/echo -e "server dynamic_radsec.${REALM} {\n${SERVERS}\n\ttype TLS\n}"
    exit 0
fi

exit 0
