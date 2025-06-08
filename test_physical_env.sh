#!/bin/bash

#######################################################################
###### IT IS JUST SET OF COMMANDS FOR STACK TEST IN PHYSICAL ENV ######
#######################################################################

# pkt test
tcpdump -i enp130s0f1
tcpdump -i enp131s0f1

hping3 --icmp -c 1000 -d 64 -i u10 192.168.1.6

nping --icmp --source-ip 192.168.1.5 --interface enp130s0f1 192.168.1.6
nping --icmp        -q -c 1000000 --rate 10000 --source-ip 192.168.1.5 --interface enp130s0f1 192.168.1.6
nping --udp -p 6666 -q -c 1000000 --rate 10000 --source-ip 192.168.1.5 --interface enp130s0f1 192.168.1.6

ping -q -c 100 -s 64 -i 0.00001 192.168.1.6
ping -q -c 500 -s 64 -i 0.00001 192.168.1.6
ping -q -c 1000 -s 64 -i 0.00001 192.168.1.6
ping -q -c 5000 -s 64 -i 0.00001 192.168.1.6
ping -q -c 10000 -s 64 -i 0.00001 192.168.1.6
ping -q -c 50000 -s 64 -i 0.00001 192.168.1.6
ping -q -c 100000 -s 64 -i 0.00001 192.168.1.6
ping -q -c 500000 -s 64 -i 0.00001 192.168.1.6
ping -q -c 1000000 -s 64 -i 0.00001 192.168.1.6

ping -q -c 100 -s 64 -i 0.00001 172.17.0.2
ping -q -c 500 -s 64 -i 0.00001 172.17.0.2
ping -q -c 1000 -s 64 -i 0.00001 172.17.0.2
ping -q -c 5000 -s 64 -i 0.00001 172.17.0.2
ping -q -c 10000 -s 64 -i 0.00001 172.17.0.2
ping -q -c 50000 -s 64 -i 0.00001 172.17.0.2
ping -q -c 100000 -s 64 -i 0.00001 172.17.0.2
ping -q -c 500000 -s 64 -i 0.00001 172.17.0.2
ping -q -c 1000000 -s 64 -i 0.00001 172.17.0.2

ping -q -c 100 -s 64 -i 0.00001 192.168.0.2
ping -q -c 500 -s 64 -i 0.00001 192.168.0.2
ping -q -c 1000 -s 64 -i 0.00001 192.168.0.2
ping -q -c 5000 -s 64 -i 0.00001 192.168.0.2
ping -q -c 10000 -s 64 -i 0.00001 192.168.0.2
ping -q -c 50000 -s 64 -i 0.00001 192.168.0.2
ping -q -c 100000 -s 64 -i 0.00001 192.168.0.2
ping -q -c 500000 -s 64 -i 0.00001 192.168.0.2
ping -q -c 1000000 -s 64 -i 0.00001 192.168.0.2

# bind/unbind physical interface
lspci
ifconfig enp131s0f1
ip addr show dev enp131s0f1
dpdk-devbind.py -s
dpdk-devbind.py -u 0000:83:00.1
dpdk-devbind.py --bind=ixgbe    0000:83:00.1
dpdk-devbind.py --bind=vfio-pci 0000:83:00.1

# configure interface
ifconfig enp130s0f1 192.168.1.5/24
ifconfig enp131s0f1 192.168.1.6/24 

netns=ns1
if1=enp130s0f1
if2=enp131s0f1

ip netns add $netns
ip link set down dev $if1
ip link set down dev $if2
ip link set dev $if2 netns $netns
ip address add 192.168.1.5/24 dev $if1
ip netns exec $netns ip address add 192.168.1.6/24 dev $if2
ip address show
ip netns exec $netns ip address show
ip link set up dev $if1
ip netns exec $netns ip link set up dev $if2
ip netns exec $netns ip link set up dev lo
ip route show
ip netns exec $netns ip route show
ping 192.168.1.6
ip netns exec $netns ping 192.168.1.5
ip netns exec $netns ip link set $if2 netns 1
