#!/bin/bash

set -e
set -x

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib:/usr/local/lib:/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu/dpdk
sleep 5
/usr/bin/fwdd -l 0-3 -n 4 --vdev=net_af_xdp1,iface=eth1
