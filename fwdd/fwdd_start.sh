#!/bin/bash

set -e
set -x

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib:/usr/local/lib:/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu/dpdk
sleep 5
/usr/bin/fwdd -l 0-3 -n 4 --vdev=net_af_xdp1,iface=eth1
# /usr/bin/fwdd -l 0-3 -n 4 --vdev=net_pcap1,iface=eth1
# /usr/bin/fwdd -l 0-3 -n 4 --vdev=net_af_packet1,iface=eth1
# /usr/bin/fwdd -l 0-3 -n 4 -- --no-mac-updates --no-promiscuous -w 0000:83:00.1
