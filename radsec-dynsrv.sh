#! /bin/sh

# Example script!
# This script looks up radsec srv records in DNS for the one
# realm given as argument, and creates a server template based
# on that. It currently ignores any weight or priority markers.

usage() {
   echo "Usage: ${0} <realm>"
   exit 1
}

test -n "${1}" || usage

REALM="${1}"
DIGCMD=$(command -v dig)
HOSTCMD=$(command -v host)

dig_it() {
   ${DIGCMD} +short srv _radsec._tcp.${REALM} |
   while read line ; do
      set $line ; PORT=$3 ; HOST=$4 
      echo "\thost ${HOST%.}:${PORT}"
   done
}

host_it() {
   ${HOSTCMD} -t srv _radsec._tcp.${REALM} |
   while read line ; do
      set $line ; PORT=$7 ; HOST=$8 
      echo "\thost ${HOST%.}:${PORT}"
   done
}

if test -x "${DIGCMD}" ; then
   SERVERS=$(dig_it)
elif test -x "${HOSTCMD}" ; then
   SERVERS=$(host_it)
else
   echo "${0} requires either \"dig\" or \"host\" command."
   exit 1
fi

if test -n "${SERVERS}" ; then
        echo "server dynamic_radsec.${REALM} {\n${SERVERS}\n\ttype TLS\n}"
        exit 0
fi

exit 0
