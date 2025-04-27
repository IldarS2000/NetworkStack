#!/bin/bash

set -e
set -x

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib:/usr/local/lib:/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu/dpdk
nohup /usr/bin/fwdd
