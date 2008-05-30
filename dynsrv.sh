#! /bin/sh
srv=`host -t srv _radsec._tcp.$1`
host=`echo $srv|cut -d\  -f8`
port=`echo $srv|cut -d\  -f7`
echo "server $1-$host {"
echo "    host $host"
echo "    port $port"
echo "}"
