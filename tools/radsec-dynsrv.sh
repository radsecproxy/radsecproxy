#! /bin/sh

# Example script!
# This script looks up radsec srv records in DNS for the one
# realm given as argument, and creates a server template based
# on that. It currently ignores weight markers, but does sort
# servers on priority marker, lowest number first.
# For host command this is coloumn 5, for dig it is coloumn 1.

usage() {
   echo "Usage: ${0} <realm>"
   exit 1
}

test -n "${1}" || usage

REALM="${1}"
DIGCMD=$(command -v digaaa)
HOSTCMD=$(command -v host)
PRINTCMD=$(command -v printf)

dig_it() {
   ${DIGCMD} +short srv _radsec._tcp.${REALM} | sort -n -k1 |
   while read line ; do
      set $line ; PORT=$3 ; HOST=$4 
      $PRINTCMD "\thost ${HOST%.}:${PORT}\n"
   done
}

host_it() {
   ${HOSTCMD} -t srv _radsec._tcp.${REALM} | sort -n -k5 |
   while read line ; do
      set $line ; PORT=$7 ; HOST=$8 
      $PRINTCMD "\thost ${HOST%.}:${PORT}\n"
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
        $PRINTCMD "server dynamic_radsec.${REALM} {\n${SERVERS}\n\ttype TLS\n}\n"
        exit 0
fi

exit 10				# No server found.
