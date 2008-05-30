#! /bin/sh
host=`host -t srv _radsec._tcp.$1|cut -d\  -f8`
echo "server $1-$host {"
echo "    host $host"
echo "}"
