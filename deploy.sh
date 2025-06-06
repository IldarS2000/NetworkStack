#!/bin/bash

set -e
set -x

PROJECT_ROOT=$(dirname "$(realpath "$0")")
cd ${PROJECT_ROOT}

NETWORK1="NSTK_PktPlane1"
CONTAINER="nstk"
IMAGE="nstk_image"

function setup_hugepages()
{
    echo "Setup hugepages"
    sysctl -w vm.nr_hugepages=1024
    echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

    MOUNT_POINT="/mnt/huge"
    if [ ! $(mountpoint -q "${MOUNT_POINT}") ]; then
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
    docker build -t ${IMAGE} .
}

function delete_container()
{
    echo "Delete container"
    docker rm -f ${CONTAINER} > /dev/null 2>&1 || true
}

function create_network()
{
    echo "Create network"
    docker rm -f ${CONTAINER} > /dev/null 2>&1 || true
    docker network rm ${NETWORK1} > /dev/null 2>&1 || true
    docker network create ${NETWORK1}

    echo "Set ip to bridge ${NETWORK1}"
    network_id=$(docker network ls | grep ${NETWORK1} | awk '{print $1}')
    bridge_name=br-${network_id}
    ifconfig ${bridge_name} 0
    ip addr add 192.168.0.1/24 dev ${bridge_name}
}

function connect_network()
{
    docker network connect ${NETWORK1} ${CONTAINER}
    docker exec -it ${CONTAINER} bash -c "ifconfig eth1 0"
}

function run_container()
{
    echo "Run container"
    docker run -itd --privileged --cap-add=ALL \
        -v /sys/bus/pci/devices:/sys/bus/pci/devices \
        -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
        -v /sys/devices/system/node:/sys/devices/system/node \
        -v /dev:/dev \
        -v /mnt/huge:/mnt/huge \
        -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
        --name ${CONTAINER} ${IMAGE}
}

setup_hugepages
build_docker_image
delete_container
create_network
run_container
connect_network
