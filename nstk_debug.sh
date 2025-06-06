#!/bin/bash

#######################################################
###### IT IS JUST SET OF COMMANDS FOR DEBUG NSTK ######
#######################################################

# fwdctl cfg
fwdctl ip add 192.168.0.2/24 eth1
fwdctl ip del 192.168.0.2/24 eth1

fwdctl if up eth1
fwdctl if down eth1

# debug
fwdctl trace enable; tail -F /var/log/nstk_trace.log
fwdctl trace disable
cat /var/log/nstk.log
gdb attach $(pidof fwdd)
tcpdump -i eth1 -e -xx
