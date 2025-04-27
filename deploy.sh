#!/bin/bash

set -e
set -x

PROJECT_ROOT=$(dirname "$(realpath "$0")")
cd ${PROJECT_ROOT}

function setup_hugepages()
{
    echo "Setup hugepages"
    sysctl -w vm.nr_hugepages=1024
    echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

    MOUNT_POINT="/mnt/huge"
    if [ ! mountpoint -q "${MOUNT_POINT}" ]; then
        echo "Mounting hugepages"
        mkdir -p ${MOUNT_POINT}
        mount -t hugetlbfs nodev ${MOUNT_POINT}
    else
        echo "Hugepages are already mounted at ${MOUNT_POINT}"
    fi
}

function build_docker_image()
{
    echo "Build docker image"
    docker build -t nstk_image .
}

function create_network()
{
    docker network create NSTK_PktPlane1 || true
    ip link add veth-host1 type veth peer name veth-container1 || true 
    ip link set up veth-host1
    ip link set up veth-container1
    network_id=$(docker network ls --filter name=NSTK_PktPlane1 --format "{{.ID}}")
    brctl addif br-${network_id} veth-host1
    ns=$(docker inspect --format '{{.State.Pid}}' nstk)
    ip link set veth-container1 netns ${ns}
}

function run_container()
{
    echo "Delete old container"
    docker rm -f nstk || true
    echo "Run container"
    docker run -itd --privileged --cap-add=ALL \
        -v /sys/bus/pci/devices:/sys/bus/pci/devices \
        -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
        -v /sys/devices/system/node:/sys/devices/system/node \
        -v /dev:/dev \
        -v /mnt/huge:/mnt/huge \
        -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
        --name nstk nstk_image
}

setup_hugepages
build_docker_image
run_container
