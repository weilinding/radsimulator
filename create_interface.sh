#!/bin/bash

if [ $# -lt 3 ]
then
    echo "Usage: $0 <ifname> <num> <ip> <action 1:delete>"
    echo "     where <ip> are base interface IP Address"
    echo "     interface <ifname>:1 to <ifname>:<num> will be created."
    echo "     ip address from <ip> to <ip+(number-1)> "
    echo "     subnet is always 255.255.0.0"
    exit 1
fi

ifname=$1
max=$2
IP_ADDR=$3
if [ $# -eq 4 ]; then
action=1
else
action=0
fi

ip=0
for I in $(echo ${IP_ADDR}| sed -e "s/\./ /g"); do 
   ip1=$I
   let ip2=$ip*256 
   let ip=$ip2+$ip1
done
for ((i=1;i<=$max;i++))
do
	let ip1=$ip/16777216
	let ip2=$ip/65536%256
	let ip3=$ip/256%256
	let ip4=$ip%256

	ipaddr=$ip1.$ip2.$ip3.$ip4
	if [ $action -eq 1 ]; then
	sudo ifconfig $ifname:$i del $ipaddr
	echo interface $ifname:$i $ipaddr/255.255.0.0 is deleted 
	else
	sudo ifconfig $ifname:$i $ipaddr netmask 255.255.0.0
	echo interface $ifname:$i $ipaddr/255.255.0.0 is created
	fi
        ip=$[ip+1]
done
