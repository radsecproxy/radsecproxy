#! /bin/sh
host -t srv _radsec._tcp.$1|cut -d\  -f8
