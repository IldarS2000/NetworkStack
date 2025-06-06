#!/bin/bash

apt update
apt install -y cmake
apt install -y dpdk=21.11.6-0ubuntu0.22.04.2
apt install -y dpdk-dev=21.11.6-0ubuntu0.22.04.2
apt install -y iputils-ping net-tools
apt install -y docker.io
