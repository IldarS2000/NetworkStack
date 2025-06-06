#!/bin/bash

###### IT IS JUST SET OF COMMANDS FOR CONFIGURING/DEVELOPING NSTK, DONT CALL IT DIRECTLY!

# fwdctl cfg
fwdctl ip add 192.168.0.2/24 eth1
fwdctl ip del 192.168.0.2/24 eth1

fwdctl if up eth1
fwdctl if down eth1

# debug
fwdctl trace enable; tail -f /var/log/nstk_trace.log
fwdctl trace disable
cat /var/log/nstk.log
gdb attach $(pidof fwdd)