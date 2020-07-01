#!/bin/bash

br_name=tpbr0
eth=p11p1
tn=tap  #tap-0/tap-1 ...

NETWORK=192.168.164.0
NETMASK=255.255.255.0
BR_IP=192.168.164.1

tun_num=50
br_name=tpbr0

enable_ip_forward() {
	sysctl net.ipv4.ip_forward=1
}

flush_iptables() {
	iptables --flush            # Flush all the rules in filter and nat tables
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain # Delete all chains that are not in default filter and nat table
}

setup_dev()  {
	echo "set up net bridge"
	brctl addbr $br_name
	ip addr add ${BR_IP}/24 dev $br_name
	ip link set $br_name up
	ip route add ${NETWORK}/24 dev $br_name

	echo "set up TAP interfaces"
	for ((i=0; i<tun_num; i++)) do
	        tunctl -d ${tn}-$i &> /dev/null
		tunctl -g netdev -t ${tn}-$i
	        brctl addif $br_name ${tn}-$i
	        ip link set ${tn}-$i up
	done
}

remove_dev() {
	echo "remove TAP interfaces"
	for ((i=0; i<tun_num; i++)) do
	        tunctl -d ${tn}-$i
	done

	echo "remove net bridge"
	ip link set $br_name down && brctl delbr $br_name
	ip route del ${NETWORK}/24
}

if [ $(id -u) -ne 0 ]; then
	echo "this script should run with root privilege"
	exit 1
fi

# Validate the interface name
ifconfig $eth &> /dev/null
if [ $? -ne 0 ]; then
	echo "Invalid interface name"
	exit 1
fi

if [ $1 == "-d" ]; then
	echo "remove_dev"
	remove_dev

	flush_iptables

	exit $?
fi

#setup brdge and interfaces
setup_dev

echo "flush all iptables? <N/Y>"
read ifflush

if [ "$ifflush" = "Y" ]; then
	echo "flush iptables"
	flush_iptables
fi

enable_ip_forward

# Set up IP FORWARDing and Masquerading
iptables --table nat --append POSTROUTING --out-interface $eth -j MASQUERADE && iptables --append FORWARD --in-interface $br_name -j ACCEPT
if [ $? -ne 0 ]; then
	echo "NAT setting failed"
	exit 1
fi
